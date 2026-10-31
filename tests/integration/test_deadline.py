"""Loopback slow-response gate. User-run only when networking is authorized."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import time
import unittest

from passphrase_leak_checker.client import LeakCheckError, PwnedClient
from tests.support import OTHER


class DeadlineRequirements(unittest.TestCase):
    def test_slow_drip_cannot_extend_the_total_request_lifetime(self):
        stop = threading.Event()
        body = f'{OTHER}:0\n'.encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    for byte in body:
                        if stop.wait(0.08):
                            break
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            thread.start()
            client = PwnedClient(f'http://127.0.0.1:{server.server_port}/{{prefix}}', timeout_seconds=1)
            error = None
            start = time.monotonic()
            try:
                client.check_secret('public timeout test password')
            except LeakCheckError as exc:
                error = exc
            finally:
                elapsed = time.monotonic() - start
                stop.set()
                server.shutdown()
                thread.join(timeout=1)
            self.assertIsNotNone(error, 'A socket timeout alone allows an indefinitely slow response.')
            self.assertLess(elapsed, 1.75, 'Total deadline exceeded, even though individual reads made progress.')
