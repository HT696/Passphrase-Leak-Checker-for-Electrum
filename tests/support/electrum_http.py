"""Check host HTTP parsing and retries with in-memory connections.

Test doubles replace handshakes and socket sends. Host libraries provide
protocol selection, parsing and request middleware. Run with network access
blocked.
"""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch


class _MemoryTransport:
    def __init__(self):
        self.closed = False
        self.protocol = None

    def set_protocol(self, protocol):
        self.protocol = protocol

    def get_protocol(self):
        return self.protocol

    def get_extra_info(self, name, default=None):
        return default

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True

    def pause_reading(self):
        pass

    def resume_reading(self):
        pass


async def _protocol_from_connection(connector, proxied):
    from aiohttp import ClientTimeout
    transport = _MemoryTransport()
    parameters = dict(addr_infos=[(2, 1, 6, '', ('service.leak-checker.invalid', 443))],
                      req=Mock(), timeout=ClientTimeout(total=1, sock_connect=1), ssl=connector._ssl)
    if proxied:
        from aiohttp_socks.connector import Proxy
        stream = SimpleNamespace(writer=SimpleNamespace(transport=transport))
        with patch.object(Proxy, 'connect', new=AsyncMock(return_value=stream)):
            return await connector._wrap_create_connection(**parameters)

    async def create_connection(factory, **kwargs):
        assert kwargs['ssl'] is connector._ssl
        protocol = factory()
        transport.set_protocol(protocol)
        protocol.connection_made(transport)
        return transport, protocol

    with patch('aiohttp.connector.aiohappyeyeballs.start_connection', new=AsyncMock(return_value=Mock())), \
            patch.object(asyncio.get_running_loop(), 'create_connection', side_effect=create_connection):
        return await connector._wrap_create_connection(connector._factory, **parameters)


async def check_upstream_http_behavior():
    """Observe host defaults without PassphraseLeakChecker guards or real network I/O."""
    from aiohttp import ClientRequest, ServerDisconnectedError
    from aiohttp.http_exceptions import LineTooLong
    from electrum import util
    from electrum.network import ProxySettings

    for mode in (None, 'socks5', 'socks4'):
        proxy = None if mode is None else ProxySettings.from_dict({
            'enabled': True, 'mode': mode, 'host': '127.0.0.1', 'port': '9050'})
        for name, metadata in (('chunk extension', b'1;'), ('trailer', b'0\r\nX-Test: ')):
            async with util.make_aiohttp_session(proxy, timeout=1) as session:
                # No bound_connector here: observe the host's own parser limits.
                factory = Mock(wraps=session.connector._factory)
                session.connector._factory = factory
                transport, protocol = await _protocol_from_connection(session.connector, proxy is not None)
                try:
                    protocol.set_response_params(read_until_eof=False, auto_decompress=False)
                    parser = type(protocol._parser)
                    protocol.data_received(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + metadata)
                    payload = protocol._payload
                    assert payload is not None
                    assert protocol.exception() is None and payload.exception() is None
                    rejected = False
                    received = len(metadata)
                    for _ in range(40):
                        protocol.data_received(b'x' * 1024)
                        received += 1024
                        error = protocol.exception() or payload.exception()
                        if error is not None:
                            assert isinstance(error.__cause__, LineTooLong), 'Unexpected upstream parser failure'
                            rejected = True
                            break
                    assert rejected, f'{mode or "direct"}: host did not bound incomplete {name}'
                    if proxy is None:
                        factory.assert_called_once()
                    else:
                        factory.assert_not_called()
                    observation = f'rejected after {received} metadata bytes' if rejected else 'not rejected within 40 KiB'
                    print(f'OBSERVED: {mode or "direct"} upstream {parser.__module__}.{parser.__name__}: '
                          f'incomplete {name} {observation}; '
                          f'connector factory {"used" if factory.called else "bypassed"}')
                finally:
                    protocol.connection_lost(None)

    # Exercise the host default separately from PassphraseLeakChecker's single-attempt rule.
    async with util.make_aiohttp_session(None, timeout=1) as session:
        connection = SimpleNamespace(protocol=Mock(), close=Mock())
        session.connector.connect = AsyncMock(return_value=connection)
        with patch.object(ClientRequest, 'send', new=AsyncMock(
                side_effect=ServerDisconnectedError('public synthetic disconnect'))) as send:
            try:
                async with session.get('https://example.invalid/range/ABCDE'):
                    raise AssertionError('A disconnected response unexpectedly succeeded')
            except ServerDisconnectedError:
                pass
            assert send.await_count == 2, 'Unexpected upstream retry policy'
    print('OBSERVED: upstream retries a disconnected GET once; PassphraseLeakChecker refuses that second attempt')


async def check_http_isolation():
    """Keep lookup limits scoped to the current HTTP session."""
    from aiohttp.client_proto import ResponseHandler
    from electrum import util
    from electrum.network import ProxySettings
    from passphrase_leak_checker.electrum.http_transport import bound_connector
    from passphrase_leak_checker import LeakCheckError

    factory = util.make_aiohttp_session
    receive = ResponseHandler.data_received
    for mode in (None, 'socks5', 'socks4'):
        proxy = None if mode is None else ProxySettings.from_dict({
            'enabled': True, 'mode': mode, 'host': '127.0.0.1', 'port': '9050'})
        async with factory(proxy, timeout=1) as lookup, factory(proxy, timeout=1) as other:
            assert lookup is not other and lookup.connector is not other.connector
            other_factory = other.connector._factory
            other_connect = other.connector._wrap_create_connection
            connector_class = type(lookup.connector)
            class_connect = connector_class._wrap_create_connection
            bound_connector(lookup.connector, 128)
            assert util.make_aiohttp_session is factory
            assert ResponseHandler.data_received is receive
            assert connector_class._wrap_create_connection is class_connect
            assert other.connector._factory is other_factory
            assert other.connector._wrap_create_connection == other_connect
            # The same valid response exceeds the lookup's private budget but
            # remains usable by another session using Electrum's normal parser.
            response = b'HTTP/1.1 200 OK\r\nContent-Length: 256\r\n\r\n' + b'x' * 256
            for session in (lookup, other):
                transport, protocol = await _protocol_from_connection(session.connector, proxy is not None)
                try:
                    protocol.set_response_params(read_until_eof=False, auto_decompress=False)
                    protocol.data_received(response)
                    if session is lookup:
                        assert isinstance(protocol.exception(), LeakCheckError) and transport.closed
                    else:
                        message, payload = await protocol.read()
                        assert message.code == 200 and await payload.read() == b'x' * 256
                        assert not transport.closed and protocol.exception() is None
                finally:
                    protocol.connection_lost(None)
    print('PASS: HTTP limits are scoped to the lookup session')


async def check_http_adapter():
    from aiohttp import ClientRequest, ServerDisconnectedError
    from electrum import util
    from electrum.network import ProxySettings
    from passphrase_leak_checker.electrum.http_transport import bound_connector, ElectrumHttpTransport
    from passphrase_leak_checker import LeakCheckError

    for mode in (None, 'socks5', 'socks4'):
        proxy = None if mode is None else ProxySettings.from_dict({
            'enabled': True, 'mode': mode, 'host': '127.0.0.1', 'port': '9050'})
        async with util.make_aiohttp_session(proxy, timeout=1) as session:
            bound_connector(session.connector, 128)
            transport, protocol = await _protocol_from_connection(session.connector, proxy is not None)
            try:
                protocol.set_response_params(read_until_eof=False, auto_decompress=False)
                protocol.data_received(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;' + b'x' * 16)
                payload = protocol._payload
                assert payload is not None
                protocol.data_received(b'x' * 8192)
                assert isinstance(protocol.exception(), LeakCheckError)
                assert isinstance(payload.exception(), LeakCheckError)
                assert transport.closed
            finally:
                protocol.connection_lost(None)
        async with util.make_aiohttp_session(proxy, timeout=1) as session:
            bound_connector(session.connector, 128)
            transport, protocol = await _protocol_from_connection(session.connector, proxy is not None)
            try:
                protocol.set_response_params(read_until_eof=False, auto_decompress=False)
                protocol.data_received(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                message, payload = await protocol.read()
                assert message.code == 200 and await payload.read() == b'OK'
                assert not transport.closed
            finally:
                protocol.connection_lost(None)
        print(f'PASS: real {mode or "direct"} connection protocol enforces the wire budget')

    original_factory = util.make_aiohttp_session
    for outcome in ('success', 'disconnect', 'route change'):
        state = {'changed': False}
        sends = []

        def guard():
            if state['changed']:
                raise LeakCheckError('route changed')

        @asynccontextmanager
        async def factory(*args, **kwargs):
            # Enter the host session factory through its async context manager.
            async with original_factory(*args, **kwargs) as session:
                connection = SimpleNamespace(protocol=Mock(), close=Mock())
                session.connector.connect = AsyncMock(return_value=connection)
                yield session

        async def send_response(connection):
            sends.append(1)
            if outcome == 'success':
                response = MagicMock(status=200, connection=None, _raw_cookie_headers=(),
                    raw_headers=((b'Content-Type', b'text/plain'), (b'Content-Length', b'2')))
                response.start = AsyncMock()
                response.__aenter__ = AsyncMock(return_value=response)
                response.__aexit__ = AsyncMock(return_value=None)
                response.content.read = AsyncMock(side_effect=[b'OK', b''])
                return response
            state['changed'] = outcome == 'route change'
            raise ServerDisconnectedError('public synthetic disconnect')

        with patch.object(util, 'make_aiohttp_session', side_effect=factory), \
                patch.object(ClientRequest, 'send', side_effect=send_response):
            try:
                body = await ElectrumHttpTransport(None)._fetch('https://example.invalid/range/ABCDE',
                    {}, 1, 128, Mock(), guard)
            except LeakCheckError as exc:
                assert outcome != 'success' and 'retry' in str(exc)
            else:
                assert outcome == 'success' and body == b'OK'
        assert len(sends) == 1, 'The real host retry loop sent an extra request'
    print('PASS: real host request loop allows one valid request and refuses retries, including after a route change')
