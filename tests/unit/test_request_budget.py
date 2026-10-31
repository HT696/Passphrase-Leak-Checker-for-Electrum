"""Check HTTP deadlines through in-memory sockets."""

import io
import socket
import ssl
from threading import Event
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import (
    LeakCheckError, PwnedClient, _RequestBudget, _resolve_host,
)
from tests.support import HASH, OTHER, SUFFIX


class Wire(io.BytesIO):
    def __init__(self, data, clock, step=0, body_only=False):
        super().__init__(data)
        self.clock, self.step = clock, step
        self.slow_after = data.index(b'\r\n\r\n') + 4 if body_only else 0

    def read1(self, size=-1):
        if self.tell() >= self.slow_after:
            self.clock[0] += self.step
        return super().read1(min(size, 1) if self.step else size)


class MemorySocket:
    def __init__(self, wire):
        self.wire = wire
        self.timeouts = []
        self.sent = []
        self.target = None
        self.closed = False
        self.shutdowns = []
        self.handshakes = 0

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.target = address

    def setsockopt(self, *args):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def send(self, data):
        self.sent.append(bytes(data))
        return len(data)

    def makefile(self, mode):
        assert mode == 'rb'
        return self.wire

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        # Like a socket with an open makefile(), its file remains readable until
        # HTTPResponse closes that file, even when the connection is closed.
        self.closed = True

    def do_handshake(self):
        self.handshakes += 1


class RequestBudgetTests(unittest.TestCase):
    body = f'{OTHER}:0\n'.encode()

    def frame(self, body=None, chunked=False):
        body = self.body if body is None else body
        if chunked:
            framing = b'Transfer-Encoding: chunked\r\n'
            body = f'{len(body):X}\r\n'.encode() + body + b'\r\n0\r\n\r\n'
        else:
            framing = f'Content-Length: {len(body)}\r\n'.encode()
        return b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n' + framing + b'\r\n' + body

    def lookup(self, wire, clock, **options):
        sock = MemorySocket(wire)
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]), \
                patch('passphrase_leak_checker.client.socket.socket', return_value=sock):
            result = PwnedClient('http://127.0.0.1:8787/range/{prefix}', **options).check_secret('password')
        return result, sock

    def test_real_http_parser_and_direct_handler_work_without_network(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                clock = [0.0]
                result, sock = self.lookup(Wire(self.frame(chunked=chunked), clock), clock)
                self.assertFalse(result.is_pwned)
                self.assertEqual(sock.target, ('127.0.0.1', 8787))
                request = b''.join(sock.sent).decode()
                self.assertIn('/range/' + HASH[:5], request)
                self.assertNotIn(HASH, request)
                self.assertNotIn(SUFFIX, request)
                self.assertTrue(sock.closed)
                self.assertTrue(sock.shutdowns)

    def test_total_budget_bounds_slow_headers_and_slow_body(self):
        for body_only in (False, True):
            for chunked in (False, True):
                with self.subTest(body_only=body_only, chunked=chunked):
                    clock = [0.0]
                    wire = Wire(self.frame(chunked=chunked), clock, step=0.08, body_only=body_only)
                    with self.assertRaises(LeakCheckError):
                        self.lookup(wire, clock, timeout_seconds=1)
                    self.assertLess(clock[0], 1.09)
                    self.assertTrue(wire.closed)

    def test_reads_shorten_the_socket_timeout_as_time_is_consumed(self):
        clock = [0.0]
        _, sock = self.lookup(Wire(self.frame(), clock, step=0.001, body_only=True), clock,
                              timeout_seconds=1)
        self.assertTrue(all(0 < timeout <= 1 for timeout in sock.timeouts))
        self.assertLess(sock.timeouts[-1], sock.timeouts[0])

    def test_verified_https_handshake_and_response_use_the_same_budget(self):
        clock = [0.0]
        tcp = MemorySocket(Wire(b'', clock))
        tls = MemorySocket(Wire(self.frame(), clock))
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', 443))]
        def wrap(context, raw, **kwargs):
            self.assertIs(raw, tcp)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertEqual(kwargs['server_hostname'], 'example.invalid')
            self.assertFalse(kwargs['do_handshake_on_connect'])
            return tls
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]), \
                patch('passphrase_leak_checker.client.socket.socket', return_value=tcp), \
                patch('passphrase_leak_checker.client._resolve_host', return_value=addresses), \
                patch.object(ssl.SSLContext, 'wrap_socket', autospec=True, side_effect=wrap):
            self.assertFalse(PwnedClient('https://example.invalid/{prefix}').check_secret('password').is_pwned)
        self.assertEqual(tls.handshakes, 1)
        self.assertTrue(tcp.closed)
        self.assertTrue(tls.closed)

    def test_cancelling_a_client_prevents_future_requests(self):
        client = PwnedClient('https://example.invalid/{prefix}')
        client.cancel()
        with patch('passphrase_leak_checker.client.build_opener') as factory:
            with self.assertRaisesRegex(LeakCheckError, 'cancelled'):
                client.check_secret('password')
        factory.return_value.open.assert_not_called()

    def test_cancellation_shuts_down_active_sockets(self):
        client = PwnedClient('https://example.invalid/{prefix}')
        budget = _RequestBudget(7, client._cancelled)
        sock = MemorySocket(io.BytesIO())
        budget.track(sock)
        client._requests.add(budget)
        client.cancel()
        self.assertTrue(sock.closed)
        self.assertEqual(sock.shutdowns, [socket.SHUT_RDWR])
        with self.assertRaisesRegex(LeakCheckError, 'cancelled'):
            budget.remaining()

    def test_no_connection_is_created_after_the_deadline(self):
        clock = [0.0]
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            budget = _RequestBudget(1, Event())
            clock[0] = 1.1
            with patch('passphrase_leak_checker.client.socket.socket') as factory, self.assertRaises(TimeoutError):
                budget.connect(('127.0.0.1', 8787))
            factory.assert_not_called()

    def test_cancellation_during_socket_registration_closes_the_socket(self):
        event = Event()
        budget = _RequestBudget(1, event)
        event.set()
        sock = MemorySocket(io.BytesIO())
        with self.assertRaises(LeakCheckError):
            budget.track(sock)
        self.assertTrue(sock.closed)

    def test_numeric_endpoints_never_start_dns(self):
        for host in ('127.0.0.1', '::1'):
            with self.subTest(host=host), patch('passphrase_leak_checker.client.Thread') as thread:
                addresses = _resolve_host(host, 8787, _RequestBudget(1, Event()))
                self.assertEqual(addresses[0][-1][0], host)
                thread.assert_not_called()

    def test_busy_dns_pool_fails_without_launching_another_resolver(self):
        with patch('passphrase_leak_checker.client._DNS_SLOTS') as slots, patch('passphrase_leak_checker.client.Thread') as thread:
            slots.acquire.return_value = False
            with self.assertRaisesRegex(LeakCheckError, 'busy'):
                _resolve_host('example.invalid', 443, _RequestBudget(1, Event()))
            thread.assert_not_called()

    def test_dns_error_releases_its_slot_and_is_redacted(self):
        def inline_thread(*args, **kwargs):
            return Mock(start=kwargs['target'])
        with patch('passphrase_leak_checker.client.Thread', side_effect=inline_thread), \
                patch('passphrase_leak_checker.client._DNS_SLOTS') as slots, \
                patch('passphrase_leak_checker.client.socket.getaddrinfo', side_effect=OSError('public sentinel')):
            slots.acquire.return_value = True
            with self.assertRaisesRegex(OSError, 'DNS lookup failed'):
                _resolve_host('example.invalid', 443, _RequestBudget(1, Event()))
            slots.release.assert_called_once()

    def test_dns_wait_checks_cancellation_without_waiting_for_the_resolver(self):
        event = Event()
        budget = _RequestBudget(1, event)
        def cancel_and_reply(**kwargs):
            event.set()
            return ([], None)
        with patch('passphrase_leak_checker.client.Thread'), patch('passphrase_leak_checker.client._DNS_SLOTS') as slots, \
                patch('passphrase_leak_checker.client.Queue') as queue:
            slots.acquire.return_value = True
            queue.return_value.get.side_effect = cancel_and_reply
            with self.assertRaisesRegex(LeakCheckError, 'cancelled'):
                _resolve_host('example.invalid', 443, budget)

    def test_successful_dns_releases_its_slot_and_returns_only_addresses(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        def inline_thread(*args, **kwargs):
            return Mock(start=kwargs['target'])
        with patch('passphrase_leak_checker.client.Thread', side_effect=inline_thread), \
                patch('passphrase_leak_checker.client._DNS_SLOTS') as slots, \
                patch('passphrase_leak_checker.client.socket.getaddrinfo', return_value=addresses) as resolve:
            slots.acquire.return_value = True
            self.assertEqual(_resolve_host('example.invalid', 443, _RequestBudget(1, Event())), addresses)
            resolve.assert_called_once_with('example.invalid', 443, 0, socket.SOCK_STREAM)
            slots.release.assert_called_once()

    def test_dns_thread_start_failure_releases_the_slot(self):
        with patch('passphrase_leak_checker.client.Thread') as thread, patch('passphrase_leak_checker.client._DNS_SLOTS') as slots:
            slots.acquire.return_value = True
            thread.return_value.start.side_effect = RuntimeError('public sentinel')
            with self.assertRaisesRegex(LeakCheckError, 'resolver is unavailable'):
                _resolve_host('example.invalid', 443, _RequestBudget(1, Event()))
            slots.release.assert_called_once()

    def test_dns_results_arriving_after_the_deadline_cannot_start_a_connection(self):
        clock = [0.0]
        def late_reply(**kwargs):
            clock[0] = 1.1
            return ([], None)
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            budget = _RequestBudget(1, Event())
            with patch('passphrase_leak_checker.client.Thread'), patch('passphrase_leak_checker.client._DNS_SLOTS') as slots, \
                    patch('passphrase_leak_checker.client.Queue') as queue:
                slots.acquire.return_value = True
                queue.return_value.get.side_effect = late_reply
                with self.assertRaises(TimeoutError):
                    budget.connect(('example.invalid', 443))

    def test_multiple_connect_attempts_share_one_budget(self):
        clock = [0.0]
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))] * 2
        first, second = Mock(), Mock()
        def first_attempt(target):
            clock[0] += 0.6
            raise OSError('try next address')
        def second_attempt(target):
            clock[0] += 0.6
        first.connect.side_effect = first_attempt
        second.connect.side_effect = second_attempt
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            budget = _RequestBudget(1, Event())
            with patch('passphrase_leak_checker.client._resolve_host', return_value=addresses), \
                    patch('passphrase_leak_checker.client.socket.socket', side_effect=(first, second)):
                with self.assertRaises(TimeoutError):
                    budget.connect(('example.invalid', 443))
                self.assertLess(second.settimeout.call_args.args[0], first.settimeout.call_args.args[0])
            budget.close()
        first.close.assert_called()
        second.close.assert_called()

    def test_partial_writes_cannot_reset_the_deadline(self):
        clock = [0.0]
        sock = MemorySocket(Wire(self.frame(), clock))
        def slow_send(data):
            clock[0] += 0.26
            return 1
        sock.send = slow_send
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]), \
                patch('passphrase_leak_checker.client.socket.socket', return_value=sock):
            with self.assertRaises(LeakCheckError):
                PwnedClient('http://127.0.0.1/{prefix}', timeout_seconds=1).check_secret('password')
        self.assertLess(clock[0], 1.3)
        self.assertTrue(sock.closed)

    def test_cancelled_read_of_a_closed_stream_is_a_handled_error(self):
        from tests.unit.test_transport_contract import Response
        client = PwnedClient('https://example.invalid/{prefix}')
        response = Response(self.body)
        def cancelled_read(size):
            client.cancel()
            raise ValueError('read of closed stream')
        response.read = cancelled_read
        opener = Mock()
        opener.open.return_value = response
        with patch('passphrase_leak_checker.client.build_opener', return_value=opener), self.assertRaises(LeakCheckError):
            client.check_secret('password')
        self.assertTrue(response.closed)
        self.assertEqual(client._requests, set())
