"""Check SOCKS and TLS with loopback fixtures."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import socket
import socketserver
import ssl
import threading
import unittest
from unittest.mock import patch

from passphrase_leak_checker import PwnedClient, SocksProxy
from tests.support import SUFFIX


TLS = Path(__file__).resolve().parents[1] / 'fixtures/tls'


class SocksHandler(socketserver.BaseRequestHandler):
    def read(self, size):
        data = bytearray()
        while len(data) < size:
            part = self.request.recv(size - len(data))
            if not part:
                raise OSError('Incomplete test proxy request.')
            data.extend(part)
        return bytes(data)

    def terminated(self):
        value = bytearray()
        while len(value) <= 255:
            byte = self.read(1)
            if byte == b'\x00':
                return value.decode('ascii')
            value.extend(byte)
        raise OSError('Oversize test proxy field.')

    def handle(self):
        self.request.settimeout(2)
        try:
            version = self.read(1)
            if version == b'\x05':
                methods = self.read(self.read(1)[0])
                method = 2 if self.server.auth else 0
                if method not in methods:
                    self.request.sendall(b'\x05\xff')
                    return
                self.request.sendall(bytes((5, method)))
                if method == 2:
                    if self.read(1) != b'\x01':
                        return
                    user = self.read(self.read(1)[0])
                    password = self.read(self.read(1)[0])
                    if (user, password) != (b'public-user', b'public-password'):
                        self.request.sendall(b'\x01\x01')
                        return
                    self.request.sendall(b'\x01\x00')
                if self.read(4) != b'\x05\x01\x00\x03':
                    raise OSError('Destination must use remote DNS in this fixture.')
                host = self.read(self.read(1)[0]).decode('ascii')
                port = int.from_bytes(self.read(2), 'big')
                reply = b'\x05\x00\x00\x01' + b'\x00' * 6
            elif version == b'\x04':
                request = self.read(7)
                if request[0] != 1 or request[3:] != b'\x00\x00\x00\x01':
                    raise OSError('Destination must use SOCKS4a in this fixture.')
                port = int.from_bytes(request[1:3], 'big')
                self.terminated()  # USERID; test cases use no credentials.
                host = self.terminated()
                reply = b'\x00\x5a' + b'\x00' * 6
            else:
                raise OSError('Unexpected test proxy version.')
            if (host, port) != ('service.leak-checker.invalid', self.server.backend_port):
                raise OSError('Test proxy refuses every other destination.')
            self.server.destinations.append((host, port))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
                upstream.settimeout(2)
                upstream.connect(('127.0.0.1', port))
                self.request.sendall(reply)
                while not self.server.stop.is_set():
                    ready, _, _ = select.select([self.request, upstream], [], [], 0.05)
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is self.request else self.request).sendall(data)
        except OSError:
            # A timeout or cancellation can close either half of the relay.
            return


class SocksServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class SocksTransportTests(unittest.TestCase):
    def lookup(self, mode, auth=False):
        paths = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                body = (SUFFIX + ':12\n').encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(TLS / 'server.pem'), str(TLS / 'server-key.pem'))
        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as backend, \
                SocksServer(('127.0.0.1', 0), SocksHandler) as proxy:
            backend.socket = context.wrap_socket(backend.socket, server_side=True)
            proxy.backend_port = backend.server_port
            proxy.auth, proxy.destinations, proxy.stop = auth, [], threading.Event()
            servers = (backend, proxy)
            threads = [threading.Thread(target=lambda server=server: server.serve_forever(poll_interval=0.01), daemon=True)
                       for server in servers]
            for thread in threads:
                thread.start()
            original_wrap, original_connect = ssl.SSLContext.wrap_socket, socket.socket.connect
            client_connections = []
            caller = threading.get_ident()
            def wrap(ctx, *args, **kwargs):
                if not kwargs.get('server_side', False):
                    self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
                    self.assertTrue(ctx.check_hostname)
                    ctx.load_verify_locations(cafile=str(TLS / 'ca.pem'))
                return original_wrap(ctx, *args, **kwargs)
            def connect(sock, address):
                if threading.get_ident() == caller:
                    client_connections.append(address)
                return original_connect(sock, address)
            route = SocksProxy('127.0.0.1', proxy.server_address[1], mode,
                               'public-user' if auth else None, 'public-password' if auth else None)
            client = PwnedClient(f'https://service.leak-checker.invalid:{backend.server_port}/range/{{prefix}}', proxy=route)
            try:
                with patch.object(ssl.SSLContext, 'wrap_socket', wrap), \
                        patch.object(socket.socket, 'connect', connect), \
                        patch('socket.getaddrinfo', side_effect=AssertionError('Unexpected local DNS')) as dns:
                    self.assertEqual(client.check_secret('password').count, 12)
                dns.assert_not_called()
                self.assertEqual(client_connections, [('127.0.0.1', route.port)])
                self.assertEqual(proxy.destinations, [('service.leak-checker.invalid', backend.server_port)])
                self.assertEqual(paths, ['/range/5BAA6'])
            finally:
                client.cancel()
                proxy.stop.set()
                for server in servers:
                    server.shutdown()
                for thread in threads:
                    thread.join(timeout=1)
                    self.assertFalse(thread.is_alive())

    def test_socks5_remote_dns_and_verified_tls_over_real_loopback(self):
        self.lookup('socks5')

    def test_authenticated_socks5_over_real_loopback(self):
        self.lookup('socks5', auth=True)

    def test_socks4a_remote_dns_and_verified_tls_over_real_loopback(self):
        self.lookup('socks4')
