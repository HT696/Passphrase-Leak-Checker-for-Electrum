"""Host-session contract with memory streams, no backend or event-loop thread."""

import asyncio
from concurrent.futures import Future, TimeoutError
from contextlib import asynccontextmanager
from email.message import Message
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, AsyncMock, Mock, patch

from passphrase_leak_checker.electrum.http_transport import ElectrumHttpTransport, bound_connector
from passphrase_leak_checker.client import LeakCheckError, PwnedClient, SocksProxy
from tests.support import ENDPOINT, SUFFIX


class Context:
    def __init__(self, value):
        self.value = value
        self.closed = False

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        self.closed = True


class MemoryContent:
    def __init__(self, body):
        self.body = body
        self.sizes = []

    async def read(self, size):
        self.sizes.append(size)
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk


class ElectrumTransportTests(unittest.TestCase):
    body = (SUFFIX + ':12\n').encode()

    def setUp(self):
        self.content = MemoryContent(self.body)
        self.response = SimpleNamespace(status=200, content=self.content, raw_headers=[
            (b'Content-Type', b'text/plain'), (b'Content-Length', str(len(self.body)).encode()),
        ])
        self.response_context = Context(self.response)
        self.session = SimpleNamespace(trust_env=False, get=Mock(return_value=self.response_context),
                                       connector=SimpleNamespace(_factory=Mock(), _wrap_create_connection=AsyncMock()))
        self.session_context = Context(self.session)
        self.factory = Mock(return_value=self.session_context)
        self.proxy_factory = Mock(side_effect=lambda data: SimpleNamespace(**data))
        self.loop = SimpleNamespace(is_running=lambda: True)
        modules = {'electrum.util': SimpleNamespace(make_aiohttp_session=self.factory,
                                                    get_asyncio_loop=lambda: self.loop),
                   'electrum.network': SimpleNamespace(ProxySettings=SimpleNamespace(from_dict=self.proxy_factory))}
        self.patcher = patch.dict('sys.modules', modules)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def fetch(self, proxy=None, limit=128, inspect=None, guard=None):
        transport = ElectrumHttpTransport(proxy)
        return asyncio.run(transport._fetch('https://example.invalid/range/ABCDE',
                           {'Add-Padding': 'true'}, 3, limit, inspect or Mock(), guard or Mock()))

    def test_uses_host_session_with_explicit_snapshot_and_safe_request_options(self):
        for proxy in (None, SocksProxy('127.0.0.1', 9050, username='public-user', password='public-pass')):
            with self.subTest(proxy=proxy):
                inspect = Mock()
                self.assertEqual(self.fetch(proxy, inspect=inspect), self.body)
                host_proxy = self.factory.call_args.args[0]
                if proxy is None:
                    self.assertIsNone(host_proxy)
                else:
                    self.assertEqual(vars(host_proxy), {'enabled': True, 'mode': 'socks5',
                        'host': '127.0.0.1', 'port': '9050', 'user': 'public-user', 'password': 'public-pass'})
                self.assertEqual(self.factory.call_args.kwargs, {'headers': {'Add-Padding': 'true'}, 'timeout': 3})
                self.session.get.assert_called_with('https://example.invalid/range/ABCDE',
                    allow_redirects=False, auto_decompress=False, proxy=None, middlewares=ANY)
                self.assertIsInstance(inspect.call_args.args[1], Message)
                self.assertTrue(self.session_context.closed)
                self.assertTrue(self.response_context.closed)
                self.content.body = self.body

    def test_limit_is_enforced_while_streaming_and_contexts_are_closed(self):
        self.content.body = b'x' * 8192
        with self.assertRaises(LeakCheckError):
            self.fetch(limit=16)
        self.assertEqual(self.content.sizes, [17])
        self.assertTrue(self.session_context.closed)
        self.assertTrue(self.response_context.closed)

    def test_async_generator_host_factory_closes_on_success_and_validation_failure(self):
        # Electrum 4.8.3 returns a context manager rather than a ClientSession.
        closed = []

        @asynccontextmanager
        async def factory(*args, **kwargs):
            try:
                yield self.session
            finally:
                closed.append(True)

        self.factory.side_effect = factory
        for fail in (False, True):
            with self.subTest(validation_failure=fail):
                self.response_context.closed = False
                self.content.body = self.body
                self.content.sizes.clear()
                closed.clear()
                if fail:
                    with self.assertRaisesRegex(LeakCheckError, 'public rejection'):
                        self.fetch(inspect=Mock(side_effect=LeakCheckError('public rejection')))
                    self.assertEqual(self.content.sizes, [])
                else:
                    self.assertEqual(self.fetch(), self.body)
                self.assertEqual(closed, [True])
                self.assertTrue(self.response_context.closed)

    def test_metadata_is_validated_before_reading_a_body_and_duplicates_survive(self):
        self.response.raw_headers.append((b'Content-Length', b'38'))
        client = PwnedClient(ENDPOINT)
        with self.assertRaises(LeakCheckError):
            self.fetch(inspect=client._response_length)
        self.assertEqual(self.content.sizes, [])
        self.assertTrue(self.response_context.closed)

    def test_redirects_compression_bad_status_and_oversize_headers_are_unavailable(self):
        for status, metadata in ((302, self.response.raw_headers), (503, self.response.raw_headers),
                (200, self.response.raw_headers + [(b'Content-Encoding', b'gzip')]),
                (200, [(b'X-Test', b'x' * 65536)])):
            self.response.status, self.response.raw_headers = status, metadata
            with self.subTest(status=status, metadata_size=sum(len(v) for _, v in metadata)), \
                    self.assertRaises(LeakCheckError):
                self.fetch(inspect=PwnedClient(ENDPOINT)._response_length)
            self.assertEqual(self.content.sizes, [])

    def test_environment_proxy_setting_and_changed_routes_refuse_io(self):
        self.session.trust_env = True
        with self.assertRaises(LeakCheckError):
            self.fetch()
        self.session.get.assert_not_called()
        self.factory.reset_mock()
        with self.assertRaises(LeakCheckError):
            self.fetch(guard=Mock(side_effect=LeakCheckError('route changed')))
        self.factory.assert_not_called()

    def test_route_change_or_cancellation_during_read_releases_session(self):
        calls = [0]
        def guard():
            calls[0] += 1
            if calls[0] == 3:
                raise LeakCheckError('route changed')
        with self.assertRaises(LeakCheckError):
            self.fetch(guard=guard)
        self.assertTrue(self.response_context.closed)
        transport = ElectrumHttpTransport(None)
        self.content.body = self.body
        async def cancelled_read(size):
            transport.cancel()
            return b'x'
        self.content.read = cancelled_read
        with self.assertRaises(LeakCheckError):
            asyncio.run(transport._fetch('https://example.invalid', {}, 1, 128, Mock(), Mock()))
        self.assertTrue(self.response_context.closed)

    def test_sync_adapter_uses_host_loop_and_cancels_timeout(self):
        for timeout in (False, True):
            future = Future()
            if timeout:
                future.result = Mock(side_effect=TimeoutError)
            else:
                future.set_result(self.body)
            def scheduled(coroutine, loop):
                self.assertIs(loop, self.loop)
                coroutine.close()
                return future
            transport = ElectrumHttpTransport(None)
            with patch('asyncio.run_coroutine_threadsafe', side_effect=scheduled) as schedule:
                if timeout:
                    with self.assertRaisesRegex(LeakCheckError, 'timeout'):
                        transport.get(ENDPOINT, headers={}, timeout_seconds=1, max_response_bytes=128,
                                      inspect_response=Mock(), network_guard=Mock())
                    self.assertTrue(future.cancelled())
                else:
                    self.assertEqual(transport.get(ENDPOINT, headers={}, timeout_seconds=1,
                        max_response_bytes=128, inspect_response=Mock(), network_guard=Mock()), self.body)
                schedule.assert_called_once()
            self.assertIsNone(transport._future)

    def test_cancel_before_start_or_unavailable_host_loop_cannot_schedule_io(self):
        for cancelled in (False, True):
            transport = ElectrumHttpTransport(None)
            if cancelled:
                transport.cancel()
            else:
                self.loop.is_running = lambda: False
            with patch('asyncio.run_coroutine_threadsafe') as schedule, self.assertRaises(LeakCheckError):
                transport.get(ENDPOINT, headers={}, timeout_seconds=1, max_response_bytes=128,
                              inspect_response=Mock(), network_guard=Mock())
            schedule.assert_not_called()
            self.loop.is_running = lambda: True

    def test_active_future_is_cancelled(self):
        transport = ElectrumHttpTransport(None)
        transport._future = Future()
        transport.cancel()
        self.assertTrue(transport._future.cancelled())

    def test_wire_limit_stops_chunk_metadata_before_host_parser_buffers_it(self):
        parser = Mock(_payload=Mock())
        original_receive = parser.data_received
        connector = SimpleNamespace(_factory=lambda: parser, _wrap_create_connection=AsyncMock())
        bound_connector(connector, 16)
        guarded = connector._factory()
        guarded.data_received(b'1;' + b'x' * 10)
        guarded.data_received(b'x' * 8192)
        # Only bounded data reaches the actual host parser.
        original_receive.assert_called_once_with(b'1;' + b'x' * 10)
        parser._payload.set_exception.assert_called_once()
        parser.set_exception.assert_called_once()
        parser.transport.close.assert_called_once()

    def test_wire_limit_also_covers_headers_before_a_payload_exists(self):
        parser = Mock(_payload=None)
        original_receive = parser.data_received
        connector = SimpleNamespace(_factory=lambda: parser, _wrap_create_connection=AsyncMock())
        bound_connector(connector, 16)
        connector._factory().data_received(b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 8192)
        original_receive.assert_not_called()
        parser.set_exception.assert_called_once()
        parser.transport.close.assert_called_once()

    def test_unknown_connector_interface_fails_closed(self):
        with self.assertRaises(LeakCheckError):
            bound_connector(object(), 16)

    def test_actual_connection_protocol_is_guarded_when_factory_is_bypassed(self):
        transport = Mock()
        protocol = Mock(_payload=Mock(), transport=transport)
        transport.get_protocol.return_value = protocol
        receive = protocol.data_received
        factory = Mock(side_effect=AssertionError('SOCKS must bypass this factory in the fixture'))
        connector = SimpleNamespace(_factory=factory,
            _wrap_create_connection=AsyncMock(return_value=(transport, protocol)))
        bound_connector(connector, 16)
        connected_transport, guarded = asyncio.run(connector._wrap_create_connection())
        self.assertIs(connected_transport, transport)
        guarded.data_received(b'1;' + b'x' * 10)
        guarded.data_received(b'x' * 8192)
        receive.assert_called_once_with(b'1;' + b'x' * 10)
        transport.close.assert_called_once()
        factory.assert_not_called()

    def test_direct_factory_and_connection_guard_share_one_byte_budget(self):
        transport = Mock()
        protocol = Mock(_payload=None, transport=transport)
        transport.get_protocol.return_value = protocol
        receive = protocol.data_received
        async def connect():
            guarded = connector._factory()
            guarded.data_received(b'x' * 9)
            return transport, guarded
        connector = SimpleNamespace(_factory=lambda: protocol, _wrap_create_connection=connect)
        bound_connector(connector, 16)
        _, guarded = asyncio.run(connector._wrap_create_connection())
        guarded.data_received(b'x' * 8)
        receive.assert_called_once_with(b'x' * 9)
        transport.close.assert_called_once()

    def test_route_change_during_connection_closes_before_request_can_be_sent(self):
        transport = Mock()
        protocol = Mock(_payload=None, transport=transport)
        transport.get_protocol.return_value = protocol
        connector = SimpleNamespace(_factory=lambda: protocol,
            _wrap_create_connection=AsyncMock(return_value=(transport, protocol)))
        guard = Mock(side_effect=[None, LeakCheckError('route changed')])
        bound_connector(connector, 16, guard)
        with self.assertRaisesRegex(LeakCheckError, 'route changed'):
            asyncio.run(connector._wrap_create_connection())
        transport.close.assert_called_once()

    def test_unknown_or_mismatched_connection_protocol_is_closed(self):
        for protocol in (object(), Mock(_payload=None)):
            transport = Mock()
            transport.get_protocol.return_value = object()
            connector = SimpleNamespace(_factory=Mock(),
                _wrap_create_connection=AsyncMock(return_value=(transport, protocol)))
            bound_connector(connector, 16)
            with self.assertRaises(LeakCheckError):
                asyncio.run(connector._wrap_create_connection())
            transport.close.assert_called_once()

    def test_single_attempt_middleware_forwards_only_one_request(self):
        self.fetch()
        middleware, = self.session.get.call_args.kwargs['middlewares']
        handler = AsyncMock(return_value='public response')
        async def attempts():
            self.assertEqual(await middleware(Mock(), handler), 'public response')
            with self.assertRaisesRegex(LeakCheckError, 'retry'):
                await middleware(Mock(), handler)
        asyncio.run(attempts())
        handler.assert_awaited_once()


class DelegatedClientTests(unittest.TestCase):
    def test_host_transport_shares_core_parsing_and_omits_hash_from_result(self):
        transport = Mock()
        body = (SUFFIX + ':12\n').encode()
        def get(url, **kwargs):
            metadata = Message()
            metadata['Content-Type'] = 'text/plain'
            metadata['Content-Length'] = str(len(body))
            kwargs['network_guard']()
            kwargs['inspect_response'](200, metadata)
            return body
        transport.get.side_effect = get
        client = PwnedClient(ENDPOINT, transport=transport)
        with patch('passphrase_leak_checker.client.build_opener') as standalone:
            result = client.check_secret('password')
        self.assertEqual(result.count, 12)
        self.assertIsNone(result.sha1_hash)
        standalone.assert_not_called()
        client.cancel()
        transport.cancel.assert_called_once()

    def test_missing_metadata_errors_and_bad_body_are_never_clean_results(self):
        transport = Mock()
        for body in (b'', b'{}', 'text', b'\xff'):
            transport.get.return_value = body
            with self.subTest(body=body), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, transport=transport).check_secret('password')
        transport.get.side_effect = RuntimeError('sensitive diagnostic')
        with self.assertRaises(LeakCheckError) as raised:
            PwnedClient(ENDPOINT, transport=transport).check_secret('password')
        self.assertNotIn('sensitive', str(raised.exception))
