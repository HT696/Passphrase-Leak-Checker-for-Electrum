"""Use Electrum's verified TLS, SOCKS connector and asyncio loop.

Bound received data, disable redirects and decompression, and support
cancellation. The shared client validates responses.
"""

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from email.message import Message
from threading import Event, Lock
from weakref import WeakSet

from .pwned_api import LeakCheckError, MAX_HTTP_METADATA_BYTES


def bound_connector(connector, limit, network_guard=None):
    """Limit received bytes before host parsing.

    Wrap both protocol creation and connection completion because SOCKS
    connectors can bypass _factory. Limits apply to this connector instance.
    """
    factory = getattr(connector, '_factory', None)
    connect = getattr(connector, '_wrap_create_connection', None)
    if not callable(factory) or not callable(connect):
        raise LeakCheckError('Electrum HTTP response limits are unavailable.')
    protected = WeakSet()

    def protect(protocol):
        if protocol in protected:
            return protocol
        if (not all(callable(getattr(protocol, name, None))
                    for name in ('data_received', 'set_exception', 'force_close'))
                or not hasattr(protocol, '_payload') or not hasattr(protocol, 'transport')):
            raise LeakCheckError('Electrum HTTP response limits are unavailable.')
        receive = protocol.data_received
        consumed = 0

        def bounded_receive(data):
            nonlocal consumed
            consumed += len(data)
            if consumed > limit:
                error = LeakCheckError('Response wire-size limit exceeded.')
                transport = protocol.transport
                try:
                    payload = protocol._payload
                    if payload is not None:
                        payload.set_exception(error)
                    protocol.set_exception(error)
                    protocol.force_close()
                finally:
                    if transport is not None:
                        transport.close()
                return
            receive(data)

        protocol.data_received = bounded_receive
        protected.add(protocol)
        return protocol

    def bounded_factory():
        return protect(factory())

    async def bounded_connect(*args, **kwargs):
        if network_guard is not None:
            network_guard()
        transport, protocol = await connect(*args, **kwargs)
        try:
            # With no await here, the event loop cannot deliver data before
            # the SOCKS protocol is guarded. Direct protocols are guarded by
            # the factory.
            if transport.get_protocol() is not protocol or protocol.transport is not transport:
                raise LeakCheckError('Electrum HTTP response limits are unavailable.')
            protect(protocol)
            if network_guard is not None:
                network_guard()
        except Exception:
            transport.close()
            raise
        return transport, protocol

    connector._factory = bounded_factory
    connector._wrap_create_connection = bounded_connect


class ElectrumHttpTransport:
    def __init__(self, proxy):
        self._proxy = proxy
        self._cancelled = Event()
        self._lock = Lock()
        self._future = None

    def cancel(self):
        self._cancelled.set()
        with self._lock:
            if self._future is not None:
                self._future.cancel()

    def get(self, url, *, headers, timeout_seconds, max_response_bytes,
            inspect_response, network_guard):
        from electrum.util import get_asyncio_loop

        loop = get_asyncio_loop()
        if not loop.is_running():
            raise LeakCheckError('Electrum networking is unavailable.')
        with self._lock:
            if self._cancelled.is_set():
                raise LeakCheckError('Lookup cancelled.')
            if self._future is not None:
                raise LeakCheckError('A lookup is already running.')
            coroutine = self._fetch(url, headers, timeout_seconds, max_response_bytes,
                                    inspect_response, network_guard)
            try:
                future = asyncio.run_coroutine_threadsafe(coroutine, loop)
            except Exception:
                coroutine.close()
                raise
            self._future = future
        try:
            return future.result(timeout=timeout_seconds)
        except FutureTimeout:
            future.cancel()
            raise LeakCheckError('Network timeout.') from None
        finally:
            with self._lock:
                self._future = None

    async def _fetch(self, url, headers, timeout, limit, inspect_response, network_guard):
        from electrum.network import ProxySettings
        from electrum.util import make_aiohttp_session

        proxy = self._proxy
        host_proxy = None if proxy is None else ProxySettings.from_dict({
            'enabled': True, 'mode': proxy.mode, 'host': proxy.host, 'port': str(proxy.port),
            'user': proxy.username, 'password': proxy.password,
        })
        network_guard()
        if self._cancelled.is_set():
            raise LeakCheckError('Lookup cancelled.')
        async with make_aiohttp_session(host_proxy, headers=headers, timeout=timeout) as session:
            # ClientSession's explicit proxy connector comes from the host factory.
            # Refuse environment routing rather than accepting an unknown factory.
            if session.trust_env:
                raise LeakCheckError('Environment proxy routing is not allowed.')
            def guard():
                network_guard()
                if self._cancelled.is_set():
                    raise LeakCheckError('Lookup cancelled.')

            bound_connector(session.connector, limit + MAX_HTTP_METADATA_BYTES, guard)
            attempted = False

            async def send_once(request, handler):
                nonlocal attempted
                if attempted:
                    raise LeakCheckError('The connection closed. Start a new leak check to retry.')
                attempted = True
                guard()
                return await handler(request)

            async with session.get(url, allow_redirects=False, auto_decompress=False,
                                   proxy=None, middlewares=(send_once,)) as response:
                metadata = Message()
                if sum(len(key) + len(value) + 4 for key, value in response.raw_headers) > MAX_HTTP_METADATA_BYTES:
                    raise LeakCheckError('Response headers exceed the size limit.')
                for key, value in response.raw_headers:
                    metadata[key.decode('ascii')] = value.decode('latin-1')
                inspect_response(response.status, metadata)
                body = bytearray()
                while True:
                    network_guard()
                    if self._cancelled.is_set():
                        raise LeakCheckError('Lookup cancelled.')
                    chunk = await response.content.read(min(65536, limit + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > limit:
                        raise LeakCheckError('Response exceeds the size limit.')
                return bytes(body)
