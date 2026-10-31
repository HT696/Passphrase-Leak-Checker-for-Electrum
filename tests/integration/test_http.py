import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from passphrase_leak_checker.electrum.network_policy import get_network_proxy
from passphrase_leak_checker.client import LeakCheckError, PwnedClient
from tests.support import HASH, SUFFIX, OTHER, policy


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.requests.append((self.path, dict(self.headers)))
                route = self.path.split('/')[1]
                body = f'{OTHER}:0\r\n'.encode()
                status = {'empty': 204, 'redirect': 302, 'error': 500}.get(route, 200)
                self.send_response(status)
                if route == 'redirect':
                    self.send_header('Location', '/range/' + HASH[:5])
                if route != 'no_type':
                    self.send_header('Content-Type', 'text/html' if route == 'html' else 'text/plain; charset=utf-8')
                if route == 'invalid_utf8':
                    body = b'\xff'
                elif route == 'bad_row':
                    body += b'malformed\n'
                elif route == 'zero_body':
                    body = b''
                if route == 'gzip':
                    self.send_header('Content-Encoding', 'gzip')
                if route == 'duplicate_length':
                    self.send_header('Content-Length', str(len(body)))
                if route in ('broken_chunk', 'valid_chunk'):
                    self.send_header('Transfer-Encoding', 'chunked')
                    body = (b'FF\r\nshort\r\n' if route == 'broken_chunk' else
                            f'{len(body):X}\r\n'.encode() + body + b'\r\n0\r\n\r\n')
                elif route != 'no_framing':
                    self.send_header('Content-Length', str(len(body) + (10 if route == 'truncated' else 0)))
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, *args):
                pass

        cls.server = HTTPServer(('127.0.0.1', 0), Handler)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=lambda: cls.server.serve_forever(poll_interval=0.01), daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=1)

    def test_direct_route_ignores_environment_proxy(self):
        config, network = policy()
        env = {'http_proxy': 'http://127.0.0.1:1', 'https_proxy': 'http://127.0.0.1:1',
               'HTTP_PROXY': 'http://127.0.0.1:1', 'HTTPS_PROXY': 'http://127.0.0.1:1',
               'no_proxy': '', 'NO_PROXY': ''}
        with patch.dict(os.environ, env), patch('socket.getaddrinfo') as dns:
            client = PwnedClient(self.base + '/range/{prefix}',
                                 network_guard=lambda: get_network_proxy(config, network))
            self.assertFalse(client.check_secret('password').is_pwned)
            dns.assert_not_called()  # Literal IPs connect directly, without DNS.
        path, headers = self.requests[-1]
        self.assertEqual(path, '/range/' + HASH[:5])
        self.assertNotIn(HASH, repr((path, headers)))
        self.assertNotIn(SUFFIX, repr((path, headers)))

    def test_invalid_http_responses_are_unavailable(self):
        for route in ('empty', 'redirect', 'error', 'html', 'no_type', 'invalid_utf8',
                      'bad_row', 'zero_body', 'gzip', 'duplicate_length', 'truncated', 'broken_chunk', 'no_framing'):
            before = len(self.requests)
            with self.subTest(route=route), self.assertRaises(LeakCheckError):
                PwnedClient(self.base + '/' + route + '/{prefix}', timeout_seconds=1).check_secret('password')
            self.assertEqual(len(self.requests), before + 1)  # Redirects and retries are rejected.

    def test_size_limit(self):
        with self.assertRaises(LeakCheckError):
            PwnedClient(self.base + '/range/{prefix}', max_response_bytes=10).check_secret('password')

    def test_complete_chunked_range_is_valid(self):
        result = PwnedClient(self.base + '/valid_chunk/{prefix}').check_secret('password')
        self.assertFalse(result.is_pwned)

    def test_invalid_host_routes_make_no_requests_even_to_loopback(self):
        for args in (policy(offline=True), policy(configured_proxy=True), policy(active_proxy=True)):
            before = len(self.requests)
            with patch('socket.getaddrinfo') as dns, patch('socket.socket.connect') as connect:
                client = PwnedClient(self.base + '/range/{prefix}',
                                     network_guard=lambda: get_network_proxy(*args))
                with self.assertRaises(LeakCheckError):
                    client.check_secret('password')
                dns.assert_not_called()
                connect.assert_not_called()
            self.assertEqual(len(self.requests), before)
