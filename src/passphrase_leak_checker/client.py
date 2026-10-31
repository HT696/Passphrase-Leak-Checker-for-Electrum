import hashlib
import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import partial
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse, HTTPException
from queue import Empty, Queue
from threading import BoundedSemaphore, Event, Lock, Thread
from typing import Callable, Dict
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

MODE_K_ANONYMITY = "k_anonymity"
MODE_FULL_HASH = "full_hash"
SUPPORTED_MODES = {MODE_K_ANONYMITY, MODE_FULL_HASH}
DEFAULT_USER_AGENT = "PassphraseLeakChecker/0.1.0"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_HTTP_METADATA_BYTES = 64 * 1024
MAX_COUNT = 2**63 - 1
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]+")
_FIELD_RE = re.compile(r"\{(prefix|suffix|hash)\}")
_RANGE_ROW_RE = re.compile(r"([A-Fa-f0-9]{35}):([0-9]{1,19})")
_DNS_SLOTS = BoundedSemaphore(4)


class LeakCheckError(Exception):
    """An unavailable or invalid lookup."""


@dataclass(frozen=True)
class SocksProxy:
    """Explicit SOCKS route. Destination names are resolved by the proxy."""
    host: str
    port: int
    mode: str = 'socks5'
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if (self.mode not in ('socks5', 'socks4') or not isinstance(self.host, str)
                or not self.host or type(self.port) is not int or not 1 <= self.port <= 65535):
            raise LeakCheckError('Invalid SOCKS proxy configuration.')
        authority = f'[{self.host}]' if ':' in self.host else self.host
        parsed = PwnedClient._validate_url(f'https://{authority}:{self.port}/')
        if parsed.hostname != self.host.lower() or parsed.port != self.port or parsed.path != '/':
            raise LeakCheckError('Invalid SOCKS proxy host.')
        for value in (self.username, self.password):
            if value is not None and not isinstance(value, str):
                raise LeakCheckError('Invalid SOCKS proxy credentials.')
            if value is not None:
                try:
                    encoded = value.encode('utf-8')
                except UnicodeError:
                    raise LeakCheckError('Invalid SOCKS proxy credentials.') from None
                if len(encoded) > 255 or b'\x00' in encoded:
                    raise LeakCheckError('Invalid SOCKS proxy credentials.')
        # Empty strings and missing credentials are equivalent for host settings.
        object.__setattr__(self, 'username', self.username or None)
        object.__setattr__(self, 'password', self.password or None)
        if self.mode == 'socks5' and bool(self.username) != bool(self.password):
            raise LeakCheckError('SOCKS5 authentication requires both username and password.')
        if self.mode == 'socks4' and self.password:
            raise LeakCheckError('SOCKS4 cannot honor a proxy password; use SOCKS5.')


class LeakCheckOutcome(Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _resolve_host(host, port, budget):
    """Bound the caller's DNS wait and the number of outstanding resolvers.

    System getaddrinfo cannot be interrupted. A timed-out daemon only finishes
    resolving; it never connects, and retains no password or hash-bearing URL.
    """
    budget.remaining()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        address = (host, port, 0, 0) if ip.version == 6 else (host, port)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address)]
    budget.remaining()
    if not _DNS_SLOTS.acquire(blocking=False):
        raise LeakCheckError('DNS resolver is busy; lookup unavailable.')
    replies = Queue(maxsize=1)

    def resolve():
        try:
            try:
                replies.put((socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM), None))
            except Exception as exc:
                replies.put((None, exc))
        finally:
            _DNS_SLOTS.release()

    try:
        Thread(target=resolve, name='passphrase_leak_checker-dns', daemon=True).start()
    except Exception:
        _DNS_SLOTS.release()
        raise LeakCheckError('DNS resolver is unavailable.') from None
    while True:
        try:
            addresses, error = replies.get(timeout=min(0.05, budget.remaining()))
            budget.remaining()
            if error is not None:
                raise OSError('DNS lookup failed.') from None
            return addresses
        except Empty:
            continue


class _RequestBudget:
    def __init__(self, seconds, cancelled, proxy=None, max_response_bytes=MAX_RESPONSE_BYTES):
        self.expires = time.monotonic() + seconds
        self.cancelled = cancelled
        self.proxy = proxy
        self.wire_limit = max_response_bytes + MAX_HTTP_METADATA_BYTES
        self._sockets = set()
        self._lock = Lock()

    def remaining(self):
        if self.cancelled.is_set():
            raise LeakCheckError('Lookup cancelled.')
        seconds = self.expires - time.monotonic()
        if seconds <= 0:
            raise TimeoutError('Request deadline exceeded.')
        return seconds

    def track(self, sock):
        with self._lock:
            self._sockets.add(sock)
            if self.cancelled.is_set():
                self._close_socket(sock)
                raise LeakCheckError('Lookup cancelled.')

    @staticmethod
    def _close_socket(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def close(self):
        with self._lock:
            for sock in self._sockets:
                self._close_socket(sock)
            self._sockets.clear()

    def connect(self, address, timeout=None, source_address=None):
        if self.proxy is None:
            return self._connect_tcp(address, source_address)
        host, port = address
        # Validate and encode the destination before opening a socket.
        # Only the proxy endpoint reaches _connect_tcp(); destination DNS
        # resolution belongs to the proxy.
        if not isinstance(host, str) or not host.isascii() or '\x00' in host or not 1 <= len(host) <= 253:
            raise LeakCheckError('Invalid SOCKS destination.')
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        port_bytes = port.to_bytes(2, 'big')
        if self.proxy.mode == 'socks4' and ip is not None and ip.version == 6:
            raise LeakCheckError('SOCKS4 does not support IPv6 destinations.')
        sock = self._connect_tcp((self.proxy.host, self.proxy.port), source_address)
        if self.proxy.mode == 'socks5':
            method = 2 if self.proxy.username is not None else 0
            self._proxy_send(sock, bytes((5, 1, method)))
            if self._proxy_read(sock, 2) != bytes((5, method)):
                raise LeakCheckError('SOCKS5 authentication negotiation failed.')
            if method == 2:
                user, password = self.proxy.username.encode('utf-8'), self.proxy.password.encode('utf-8')
                self._proxy_send(sock, b'\x01' + bytes((len(user),)) + user + bytes((len(password),)) + password)
                if self._proxy_read(sock, 2) != b'\x01\x00':
                    raise LeakCheckError('SOCKS5 authentication failed.')
            if ip is None:
                target = b'\x03' + bytes((len(host),)) + host.encode('ascii')
            else:
                target = bytes((1 if ip.version == 4 else 4,)) + ip.packed
            self._proxy_send(sock, b'\x05\x01\x00' + target + port_bytes)
            reply = self._proxy_read(sock, 4)
            if reply[:3] != b'\x05\x00\x00':
                raise LeakCheckError('SOCKS5 connection failed; no direct fallback was attempted.')
            if reply[3] == 1:
                length = 4
            elif reply[3] == 4:
                length = 16
            elif reply[3] == 3:
                length = self._proxy_read(sock, 1)[0]
                if not length:
                    raise LeakCheckError('Invalid SOCKS5 response.')
            else:
                raise LeakCheckError('Invalid SOCKS5 response.')
            self._proxy_read(sock, length + 2)
        else:
            user = (self.proxy.username or '').encode('utf-8')
            target = ip.packed if ip is not None else b'\x00\x00\x00\x01'
            domain = host.encode('ascii') + b'\x00' if ip is None else b''
            self._proxy_send(sock, b'\x04\x01' + port_bytes + target + user + b'\x00' + domain)
            if self._proxy_read(sock, 8)[:2] != b'\x00\x5a':
                raise LeakCheckError('SOCKS4 connection failed; no direct fallback was attempted.')
        self.remaining()
        return sock

    def _proxy_send(self, sock, data):
        view = memoryview(data)
        while view:
            sock.settimeout(self.remaining())
            sent = sock.send(view)
            self.remaining()
            if not sent:
                raise LeakCheckError('Proxy connection closed.')
            view = view[sent:]

    def _proxy_read(self, sock, size):
        data = bytearray()
        while len(data) < size:
            sock.settimeout(self.remaining())
            chunk = sock.recv(size - len(data))
            self.remaining()
            if not chunk:
                raise LeakCheckError('Proxy response was incomplete.')
            data.extend(chunk)
        return bytes(data)

    def _connect_tcp(self, address, source_address=None):
        last_error = None
        for family, kind, protocol, _, target in _resolve_host(*address, self):
            self.remaining()
            sock = socket.socket(family, kind, protocol)
            try:
                self.track(sock)
                sock.settimeout(self.remaining())
                if source_address:
                    sock.bind(source_address)
                sock.connect(target)
                self.remaining()
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
            except BaseException:
                sock.close()
                raise
        if last_error is not None:
            raise last_error
        raise OSError('DNS returned no usable addresses.')


class _BudgetReader:
    """Recalculate the deadline for each underlying read, including headers."""
    def __init__(self, stream, sock, budget):
        self._stream, self._sock, self._budget = stream, sock, budget
        self._bytes_read = 0

    def __getattr__(self, name):
        return getattr(self._stream, name)

    def read1(self, size=-1):
        if size < 0:
            raise HTTPException('Unbounded response reads are forbidden.')
        available = self._budget.wire_limit - self._bytes_read
        if available <= 0:
            raise HTTPException('Response wire-size limit exceeded.')
        self._sock.settimeout(self._budget.remaining())
        data = self._stream.read1(min(size, available))
        self._bytes_read += len(data)
        self._budget.remaining()
        return data

    def read(self, size=-1):
        if size < 0:
            raise HTTPException('Unbounded response reads are forbidden.')
        chunks = []
        total = 0
        while total < size:
            chunk = self.read1(min(65536, size - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b''.join(chunks)

    def readline(self, size=-1):
        if size < 0:
            raise HTTPException('Unbounded response reads are forbidden.')
        line = bytearray()
        while size < 0 or len(line) < size:
            byte = self.read1(1)
            if not byte:
                break
            line.extend(byte)
            if byte == b'\n':
                break
        return bytes(line)


class _BudgetResponse(HTTPResponse):
    def __init__(self, sock, *args, budget, **kwargs):
        super().__init__(sock, *args, **kwargs)
        self.fp = _BudgetReader(self.fp, sock, budget)

    def _get_chunk_left(self):
        if self.chunk_left == 0:
            # stdlib discards the delimiter without validating it. Consume it
            # here, then let the existing decoder handle the next chunk.
            if self._safe_read(2) != b'\r\n':
                raise HTTPException('Invalid HTTP chunk delimiter.')
            self.chunk_left = None
        return super()._get_chunk_left()

    def _read_next_chunk_size(self):
        # http.client accepts signed sizes; a negative size becomes read(-1).
        # Keep its chunk decoder, but validate the size before it sees a value.
        line = self.fp.readline(8193)
        match = re.fullmatch(rb'([0-9A-Fa-f]{1,16})(?:;[\x20-\x7e]*)?\r\n', line)
        if match is None or len(line) > 8192:
            raise HTTPException('Invalid HTTP chunk size.')
        return int(match[1], 16)

    def _read_and_discard_trailer(self):
        # This protocol has no use for trailers. Require the complete terminal
        # blank line instead of treating an EOF as a complete chunked response.
        if self.fp.readline(3) != b'\r\n':
            raise HTTPException('HTTP trailers or incomplete chunk framing are unsupported.')


class _BudgetConnection:
    def __init__(self, *args, budget, **kwargs):
        self._budget = budget
        kwargs['timeout'] = budget.remaining()
        super().__init__(*args, **kwargs)
        self._create_connection = budget.connect
        self.response_class = partial(_BudgetResponse, budget=budget)

    def send(self, data):
        self._budget.remaining()
        if self.sock is None:
            if not self.auto_open:
                raise HTTPException('Connection is not open.')
            self.connect()
        # GET requests send bytes. Recalculate after connecting and on partial
        # writes, including TLS writes, rather than resetting a sendall timeout.
        view = memoryview(data)
        while view:
            self.sock.settimeout(self._budget.remaining())
            sent = self.sock.send(view)
            if not sent:
                raise ConnectionResetError('Connection closed during request.')
            view = view[sent:]


class _BudgetHTTPConnection(_BudgetConnection, HTTPConnection):
    pass


class _BudgetHTTPSConnection(_BudgetConnection, HTTPSConnection):
    def connect(self):
        HTTPConnection.connect(self)
        self.sock.settimeout(self._budget.remaining())
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host,
                                              do_handshake_on_connect=False)
        self._budget.track(self.sock)
        self.sock.do_handshake()
        self._budget.remaining()


class _BudgetHTTPHandler(HTTPHandler):
    def __init__(self, budget):
        super().__init__()
        self.budget = budget

    def http_open(self, request):
        return self.do_open(partial(_BudgetHTTPConnection, budget=self.budget), request)


class _BudgetHTTPSHandler(HTTPSHandler):
    def __init__(self, budget):
        # Create the standard verified TLS context lazily on actual HTTPS I/O.
        HTTPHandler.__init__(self)
        self.budget = budget
        self._context = None

    def https_open(self, request):
        self._context = HTTPSHandler()._context
        return self.do_open(partial(_BudgetHTTPSConnection, budget=self.budget), request,
                            context=self._context)


@dataclass(frozen=True)
class LeakCheckResult:
    is_pwned: bool
    count: int
    sha1_hash: str | None = field(repr=False)
    mode: str
    # Boolean-only services confirm presence without reporting a frequency.
    count_reported: bool = True

    def __post_init__(self):
        if (type(self.count) is not int or not 0 <= self.count <= MAX_COUNT
                or type(self.is_pwned) is not bool or self.is_pwned != (self.count > 0)
                or type(self.count_reported) is not bool
                or (not self.count_reported and self.count not in (0, 1))):
            raise LeakCheckError("Invalid lookup result.")

    @property
    def outcome(self) -> LeakCheckOutcome:
        return LeakCheckOutcome.MATCH if self.is_pwned else LeakCheckOutcome.NO_MATCH


def lookup_outcome(result, error) -> LeakCheckOutcome:
    """Treat missing results and errors as unavailable."""
    if error is not None or not isinstance(result, LeakCheckResult):
        return LeakCheckOutcome.UNAVAILABLE
    return result.outcome


class PwnedClient:
    def __init__(self, endpoint_template: str, mode: str = MODE_K_ANONYMITY,
                 timeout_seconds: int = 7, extra_headers: Dict[str, str] | None = None,
                 max_response_bytes: int = MAX_RESPONSE_BYTES,
                 *, full_hash_consent: bool = False,
                 network_guard: Callable[[], None] | None = None,
                 proxy: SocksProxy | None = None, transport=None,
                 include_hash: bool = False) -> None:
        if not isinstance(mode, str) or mode not in SUPPORTED_MODES:
            raise LeakCheckError("Unsupported lookup mode.")
        self._validate_endpoint_template(endpoint_template, mode=mode)
        self.endpoint_template = endpoint_template
        self.mode = mode
        self.timeout_seconds = self._integer_setting(timeout_seconds)
        self.max_response_bytes = self._integer_setting(max_response_bytes)
        if not 1 <= self.timeout_seconds <= 60 or not 1 <= self.max_response_bytes <= MAX_RESPONSE_BYTES:
            raise LeakCheckError("Timeout or response-size limit is out of range.")
        if type(full_hash_consent) is not bool:
            raise LeakCheckError("Disclosure approval must be a boolean.")
        if network_guard is not None and not callable(network_guard):
            raise LeakCheckError("Network policy guard must be callable.")
        if proxy is not None and type(proxy) is not SocksProxy:
            raise LeakCheckError('Proxy must be an explicit SocksProxy configuration.')
        self._proxy = proxy
        self._validate_transport_url(endpoint_template, proxy)
        if type(include_hash) is not bool:
            raise LeakCheckError('Hash output must be explicitly enabled with a boolean.')
        if transport is not None and (not callable(getattr(transport, 'get', None))
                                      or not callable(getattr(transport, 'cancel', None))):
            raise LeakCheckError('Invalid HTTP transport.')
        self._transport = transport
        self._include_hash = include_hash
        self.extra_headers = self._sanitize_headers({} if extra_headers is None else extra_headers)
        self._network_guard = network_guard
        self._cancelled = Event()
        self._requests = set()
        self._request_lock = Lock()
        self._consented_destination = self.destination if full_hash_consent is True else None

    @property
    def proxy(self):
        return self._proxy

    @property
    def destination(self) -> str:
        parsed = urlsplit(self.endpoint_template)
        return f"{parsed.scheme}://{parsed.netloc}"

    def approve_full_hash_disclosure(self, destination: str) -> None:
        if destination != self.destination:
            raise LeakCheckError("Disclosure approval does not match the destination.")
        self._consented_destination = destination

    def cancel(self):
        """Cancel this client's requests permanently; create a new client to retry."""
        self._cancelled.set()
        try:
            if self._transport is not None:
                self._transport.cancel()
        finally:
            with self._request_lock:
                for budget in self._requests:
                    budget.close()

    def check_secret(self, passphrase: str) -> LeakCheckResult:
        if not isinstance(passphrase, str) or not passphrase:
            raise LeakCheckError("Passphrase is empty or invalid.")
        if self.mode == MODE_FULL_HASH and self._consented_destination != self.destination:
            raise LeakCheckError("Full-hash lookup requires explicit approval for this destination.")
        try:
            sha1_hash = hashlib.sha1(passphrase.encode("utf-8")).hexdigest().upper()
        except UnicodeError:
            raise LeakCheckError("Passphrase cannot be encoded as UTF-8.") from None
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        raw_body = self._http_get(self._build_url(prefix, suffix, sha1_hash))
        if self.mode == MODE_K_ANONYMITY:
            count = self._parse_k_anonymity_response(raw_body, suffix)
            count_reported = True
        else:
            count, count_reported = self._parse_full_hash_response(raw_body, sha1_hash)
        if self._cancelled.is_set():
            raise LeakCheckError('Lookup cancelled.')
        return LeakCheckResult(count > 0, count, sha1_hash if self._include_hash else None,
                               self.mode, count_reported=count_reported)

    def _build_url(self, prefix: str, suffix: str, full_hash: str) -> str:
        self._validate_endpoint_template(self.endpoint_template, mode=self.mode)
        if (not re.fullmatch(r"[A-F0-9]{5}", prefix)
                or not re.fullmatch(r"[A-F0-9]{35}", suffix) or full_hash != prefix + suffix):
            raise LeakCheckError("Internal hash format error.")
        # Substitute only the prefix in range mode.
        fields = {"prefix": prefix}
        if self.mode == MODE_FULL_HASH:
            fields.update(suffix=suffix, hash=full_hash)
        url = _FIELD_RE.sub(lambda match: fields[match[1]], self.endpoint_template)
        parsed = self._validate_url(url)
        if f"{parsed.scheme}://{parsed.netloc}" != self.destination:
            raise LeakCheckError("Lookup destination changed during substitution.")
        return url

    def _http_get(self, url: str) -> str:
        self._validate_transport_url(url, self.proxy)
        headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept-Encoding": "identity"}
        headers.update(self._sanitize_headers(self.extra_headers))
        if self._transport is not None:
            return self._delegated_get(url, headers)
        request = Request(url, headers=headers)
        # Use the explicit proxy route and check Electrum policy before connecting.
        budget = _RequestBudget(self.timeout_seconds, self._cancelled, proxy=self.proxy,
                                max_response_bytes=self.max_response_bytes)
        opener = build_opener(ProxyHandler({}), _NoRedirectHandler(),
                              _BudgetHTTPHandler(budget), _BudgetHTTPSHandler(budget))
        if self._network_guard is not None:
            try:
                self._network_guard()
            except LeakCheckError:
                raise
            except Exception:
                raise LeakCheckError("Cannot verify network policy; lookup unavailable.") from None
        try:
            with self._request_lock:
                self._requests.add(budget)
            budget.remaining()
            with opener.open(request, timeout=self.timeout_seconds) as response:
                budget.remaining()
                expected_length = self._response_length(response.status, response.headers)
                body = response.read(self.max_response_bytes + 1)
                budget.remaining()
                return self._decode_body(body, expected_length)
        except HTTPError as exc:
            exc.close()
            if 300 <= exc.code < 400:
                raise LeakCheckError("Redirect responses are not allowed for leak checks.") from None
            raise LeakCheckError(f"The service returned HTTP {exc.code}.") from None
        except TimeoutError:
            raise LeakCheckError("Network timeout.") from None
        except (URLError, OSError, HTTPException, UnicodeError, ValueError):
            # Underlying errors may include hash-bearing URLs or credentials.
            raise LeakCheckError("Network or response error; lookup unavailable.") from None
        finally:
            budget.close()
            with self._request_lock:
                self._requests.discard(budget)

    def _response_length(self, status, headers):
        if status != 200:
            raise LeakCheckError('Unexpected HTTP status; lookup unavailable.')
        if (len(headers.get_all('Content-Type', [])) != 1
                or len(headers.get_all('Content-Encoding', [])) > 1):
            raise LeakCheckError('Ambiguous response content metadata.')
        allowed = {'text/plain'} if self.mode == MODE_K_ANONYMITY else {'application/json', 'text/plain'}
        if not headers.get('Content-Type') or headers.get_content_type() not in allowed:
            raise LeakCheckError('Unexpected response content type.')
        charset = headers.get_content_charset()
        if charset and charset.lower() not in {'utf-8', 'utf8', 'us-ascii', 'ascii'}:
            raise LeakCheckError('Response must use UTF-8 encoding.')
        if headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise LeakCheckError('Compressed responses are not supported.')
        lengths, transfers = headers.get_all('Content-Length', []), headers.get_all('Transfer-Encoding', [])
        if not lengths and not transfers:
            raise LeakCheckError('Response needs explicit length or chunked framing.')
        if len(lengths) > 1 or (lengths and transfers) or (transfers and transfers != ['chunked']):
            raise LeakCheckError('Ambiguous response framing.')
        if lengths:
            if not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
                raise LeakCheckError('Invalid response length.')
            length = int(lengths[0])
            if length > self.max_response_bytes:
                raise LeakCheckError('Response exceeds the size limit.')
            return length
        return None

    def _decode_body(self, body, expected_length):
        if not isinstance(body, bytes) or len(body) > self.max_response_bytes:
            raise LeakCheckError('Response exceeds the size limit or has an invalid type.')
        if expected_length is not None and len(body) != expected_length:
            raise LeakCheckError('Incomplete response; lookup unavailable.')
        return body.decode('utf-8', errors='strict')

    def _delegated_get(self, url, headers):
        expected = []

        def inspect_response(status, metadata):
            if expected:
                raise LeakCheckError('Multiple HTTP responses are not allowed.')
            expected.append(self._response_length(status, metadata))

        def guard():
            if self._cancelled.is_set():
                raise LeakCheckError('Lookup cancelled.')
            if self._network_guard is not None:
                self._network_guard()

        try:
            guard()
            body = self._transport.get(url, headers=headers, timeout_seconds=self.timeout_seconds,
                                       max_response_bytes=self.max_response_bytes,
                                       inspect_response=inspect_response, network_guard=guard)
            guard()
            if not expected:
                raise LeakCheckError('HTTP response metadata was not verified.')
            return self._decode_body(body, expected[0])
        except LeakCheckError:
            raise
        except Exception:
            raise LeakCheckError('Network or response error; lookup unavailable.') from None

    @staticmethod
    def _validate_transport_url(url, proxy):
        if urlsplit(url).scheme == 'http' and proxy is not None:
            raise LeakCheckError('HTTP test endpoints require a direct loopback connection. Use HTTPS with a proxy.')

    @staticmethod
    def _parse_k_anonymity_response(body: str, expected_suffix: str) -> int:
        expected_suffix = expected_suffix.upper()
        if not re.fullmatch(r"[A-F0-9]{35}", expected_suffix):
            raise LeakCheckError("Internal hash format error for k-anonymity lookup.")
        # Empty ranges are invalid; custom backends can return a zero-count padding row.
        lines = body.replace("\r\n", "\n").split("\n")
        if lines[-1] == "":
            lines.pop()
        if not lines:
            raise LeakCheckError("Empty range response; lookup unavailable.")
        seen = set()
        count = 0
        for line in lines:
            match = _RANGE_ROW_RE.fullmatch(line)
            if not match:
                raise LeakCheckError("Malformed range response; lookup unavailable.")
            suffix = match[1].upper()
            if suffix in seen:
                raise LeakCheckError("Duplicate suffix in range response.")
            seen.add(suffix)
            row_count = PwnedClient._coerce_count(int(match[2]))
            if suffix == expected_suffix:
                count = row_count
        return count

    @staticmethod
    def _parse_full_hash_response(body: str, expected_hash: str) -> tuple[int, bool]:
        payload = PwnedClient._load_json(body)
        if type(payload) is bool:
            return int(payload), False
        if type(payload) is int:
            return PwnedClient._coerce_count(payload), True
        if not isinstance(payload, dict):
            raise LeakCheckError("Unsupported JSON response type.")
        if set(payload) - {"count", "found", "pwned", "hash"}:
            raise LeakCheckError("Unexpected fields in full-hash response.")
        if not {"count", "found", "pwned"}.intersection(payload):
            raise LeakCheckError("Response must include count, found or pwned.")
        if "hash" in payload:
            returned_hash = payload["hash"]
            if (not isinstance(returned_hash, str)
                    or not re.fullmatch(r"[A-Fa-f0-9]{40}", returned_hash)
                    or returned_hash.upper() != expected_hash.upper()):
                raise LeakCheckError("Response hash does not match this lookup.")
        flags = []
        for name in ("found", "pwned"):
            if name in payload:
                if type(payload[name]) is not bool:
                    raise LeakCheckError("Response flags must be JSON booleans.")
                flags.append(payload[name])
        count = PwnedClient._coerce_count(payload["count"]) if "count" in payload else int(flags[0])
        if any(flag != (count > 0) for flag in flags):
            raise LeakCheckError("Contradictory fields in full-hash response.")
        return count, 'count' in payload

    @staticmethod
    def _load_json(body):
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise LeakCheckError("Duplicate JSON field in response.")
                result[key] = value
            return result

        def integer(text):
            if len(text) > 19:
                raise LeakCheckError('JSON integer exceeds the supported range.')
            return int(text)

        def constant(text):
            raise LeakCheckError('Nonfinite JSON numbers are unsupported.')

        try:
            return json.loads(body, object_pairs_hook=unique_object, parse_int=integer, parse_constant=constant)
        except (ValueError, RecursionError):
            raise LeakCheckError("Expected a complete JSON response.") from None

    @staticmethod
    def _integer_setting(value) -> int:
        # Accept decimal strings from host configuration, but never truncate
        # floats or treat JSON booleans as integer settings.
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
            return int(value)
        if type(value) is not int:
            raise LeakCheckError("Timeout and response-size limit must be integers.")
        return value

    @staticmethod
    def _coerce_count(value: object) -> int:
        if type(value) is not int or not 0 <= value <= MAX_COUNT:
            raise LeakCheckError("Count must be a nonnegative integer within the supported range.")
        return value

    @staticmethod
    def _sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
        if not isinstance(headers, dict):
            raise LeakCheckError("HTTP request headers must be an object.")
        normalized = {}
        names = set()
        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise LeakCheckError("HTTP header names and values must be text.")
            if not _HEADER_NAME_RE.fullmatch(key) or PwnedClient._contains_ctl(value):
                raise LeakCheckError("Invalid header name or value.")
            lowered = key.lower()
            if lowered in names or lowered in {"host", "accept-encoding", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection"}:
                raise LeakCheckError("Duplicate or reserved HTTP header.")
            try:
                value.encode("latin-1")
            except UnicodeError:
                raise LeakCheckError("Header value cannot be encoded for HTTP.") from None
            names.add(lowered)
            normalized[key] = value
        return normalized

    @staticmethod
    def _contains_ctl(value: str) -> bool:
        return any(ord(char) < 32 or ord(char) == 127 for char in value)

    @staticmethod
    def _validate_endpoint_template(endpoint_template: str, *, mode: str = MODE_K_ANONYMITY) -> None:
        if not isinstance(endpoint_template, str) or not endpoint_template:
            raise LeakCheckError("The service URL template is empty or invalid.")
        fields = set(_FIELD_RE.findall(endpoint_template))
        remainder = _FIELD_RE.sub("", endpoint_template)
        if "{" in remainder or "}" in remainder:
            raise LeakCheckError("Only exact {prefix}, {suffix}, and {hash} fields are allowed.")
        PwnedClient._validate_url(endpoint_template)
        if mode == MODE_K_ANONYMITY:
            if fields != {"prefix"}:
                raise LeakCheckError("Sending only the first 5 hash characters requires {prefix}; remove {hash} and {suffix} from the service URL.")
        elif mode == MODE_FULL_HASH:
            if "hash" not in fields and not {"prefix", "suffix"}.issubset(fields):
                raise LeakCheckError("Sending the full hash requires {hash}, or both {prefix} and {suffix}, in the service URL.")
        else:
            raise LeakCheckError("Unsupported lookup mode.")

    @staticmethod
    def _validate_url(url: str):
        # Check before urlsplit, which otherwise strips some control characters.
        if (not url.isascii() or any(char.isspace() for char in url)
                or PwnedClient._contains_ctl(url) or "\\" in url
                or PwnedClient._contains_ctl(unquote(url)) or "#" in url):
            raise LeakCheckError("The service URL contains unsupported characters or a fragment (#).")
        try:
            parsed = urlsplit(url)
            port = parsed.port
            host = parsed.hostname
        except ValueError:
            raise LeakCheckError("Invalid service hostname or port.") from None
        if parsed.scheme not in {"http", "https"} or not host:
            raise LeakCheckError("The service URL must begin with http:// or https:// and include a hostname.")
        if "@" in parsed.netloc or "%" in parsed.netloc or "{" in parsed.netloc or "}" in parsed.netloc:
            raise LeakCheckError("The service hostname and port must be fixed, without usernames, passwords, or URL escapes.")
        if parsed.netloc.startswith("["):
            if not re.fullmatch(r"\[[0-9A-Fa-f:]+\](?::[0-9]+)?", parsed.netloc):
                raise LeakCheckError("Invalid IPv6 service address.")
        if parsed.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535):
            raise LeakCheckError("Invalid service port.")
        if host.lower().rstrip(".").endswith(".onion"):
            raise LeakCheckError("Onion (.onion) service URLs are unsupported. No connection will be attempted.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?", host):
                raise LeakCheckError("Invalid service hostname.")
            if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                   for label in host.rstrip(".").split(".")):
                raise LeakCheckError("Invalid service hostname.")
        if parsed.scheme == "http" and not PwnedClient._is_loopback_host(host):
            raise LeakCheckError("Remote service URLs require HTTPS. HTTP is allowed only for local testing at a loopback IP (e.g. 127.0.0.1).")
        return parsed

    @staticmethod
    def _is_loopback_host(hostname: str | None) -> bool:
        # Require literal loopback IPs to avoid hostname overrides.
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False
