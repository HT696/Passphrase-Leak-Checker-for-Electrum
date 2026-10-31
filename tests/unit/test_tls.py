"""Actual certificate verification and encrypted HTTP, entirely in memory."""

import io
from pathlib import Path
import socket
import ssl
import unittest
from unittest.mock import patch

from passphrase_leak_checker.client import LeakCheckError, PwnedClient, SocksProxy
from tests.support import HASH, SUFFIX
from tests.unit.test_request_budget import MemorySocket
from tests.unit.test_socks import SocksSocket


FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures/tls'


class TLSStream(io.RawIOBase):
    def __init__(self, peer):
        self.peer = peer

    def readable(self):
        return True

    def readinto(self, buffer):
        try:
            data = self.peer.client.read(len(buffer))
        except ssl.SSLWantReadError:
            if not self.peer.responded:
                raise AssertionError('TLS test peer has no response ready.') from None
            return 0
        buffer[:len(data)] = data
        return len(data)


class TLSPeer:
    """Socket-shaped adapter; both SSLObjects use the real OpenSSL verifier."""
    def __init__(self, context, server_context, hostname, response):
        self.client_in, self.client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server_in, self.server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.client = context.wrap_bio(self.client_in, self.client_out, server_hostname=hostname)
        self.server = server_context.wrap_bio(self.server_in, self.server_out, server_side=True)
        self.response = response
        self.request = bytearray()
        self.responded = False
        self.closed = False
        self.verification_error = None

    @staticmethod
    def transfer(source, destination):
        data = source.read()
        if data:
            destination.write(data)

    def do_handshake(self):
        client_done = server_done = False
        for _ in range(20):
            if not client_done:
                try:
                    self.client.do_handshake()
                    client_done = True
                except ssl.SSLWantReadError:
                    pass
                except ssl.SSLCertVerificationError as exc:
                    self.verification_error = exc
                    raise
            self.transfer(self.client_out, self.server_in)
            if not server_done:
                try:
                    self.server.do_handshake()
                    server_done = True
                except ssl.SSLWantReadError:
                    pass
            self.transfer(self.server_out, self.client_in)
            if client_done and server_done:
                return
        raise AssertionError('TLS test handshake did not converge.')

    def send(self, data):
        written = self.client.write(data)
        self.transfer(self.client_out, self.server_in)
        while True:
            try:
                self.request.extend(self.server.read(65536))
            except ssl.SSLWantReadError:
                break
        if not self.responded and b'\r\n\r\n' in self.request:
            self.server.write(self.response)
            self.responded = True
        self.transfer(self.server_out, self.client_in)
        return written

    def makefile(self, mode):
        assert mode == 'rb'
        return io.BufferedReader(TLSStream(self))

    def settimeout(self, timeout):
        assert timeout > 0

    def shutdown(self, how):
        self.closed = True

    def close(self):
        # An HTTP response's makefile remains usable after connection.close().
        self.closed = True


class TLSVerificationTests(unittest.TestCase):
    def lookup(self, *, certificate='server', hostname='service.leak-checker.invalid', trust=True, proxy=None):
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(str(FIXTURES / (certificate + '.pem')), str(FIXTURES / 'server-key.pem'))
        body = (SUFFIX + ':12\n').encode()
        response = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        tcp = MemorySocket(io.BytesIO()) if proxy is None else SocksSocket()
        self.peers = []
        self.tcp = tcp

        def wrap(context, raw, **kwargs):
            self.assertIs(raw, tcp)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertFalse(kwargs['do_handshake_on_connect'])
            if trust:
                context.load_verify_locations(cafile=str(FIXTURES / 'ca.pem'))
            peer = TLSPeer(context, server, kwargs['server_hostname'], response)
            self.peers.append(peer)
            return peer

        port = 443 if proxy is None else proxy.port
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.0.2.1', port))]
        with patch('passphrase_leak_checker.client._resolve_host', return_value=addresses) as resolve, \
                patch('passphrase_leak_checker.client.socket.socket', return_value=tcp), \
                patch.object(ssl.SSLContext, 'wrap_socket', autospec=True, side_effect=wrap):
            result = PwnedClient('https://' + hostname + '/range/{prefix}', proxy=proxy).check_secret('password')
        self.assertEqual(resolve.call_args.args[:2], (hostname if proxy is None else proxy.host, port))
        return result

    def test_trusted_certificate_encrypts_a_prefix_only_lookup(self):
        result = self.lookup()
        self.assertEqual(result.count, 12)
        request = self.peers[0].request.decode()
        self.assertIn('GET /range/' + HASH[:5], request)
        self.assertNotIn(SUFFIX, request)
        self.assertNotIn(HASH, request)
        self.assertIsNone(self.peers[0].verification_error)
        self.assertTrue(self.peers[0].closed)

    def assert_verification_failure(self, **options):
        with self.assertRaises(LeakCheckError):
            self.lookup(**options)
        self.assertEqual(len(self.peers), 1, 'TLS failure must not retry with weaker verification.')
        peer = self.peers[0]
        self.assertIsInstance(peer.verification_error, ssl.SSLCertVerificationError)
        self.assertEqual(peer.request, b'', 'No HTTP request may precede certificate verification.')
        self.assertTrue(peer.closed)
        self.assertTrue(self.tcp.closed)

    def test_untrusted_ca_refuses_the_request(self):
        self.assert_verification_failure(trust=False)

    def test_wrong_hostname_refuses_the_request(self):
        self.assert_verification_failure(hostname='different.leak-checker.invalid')

    def test_expired_certificate_refuses_the_request(self):
        self.assert_verification_failure(certificate='expired')

    def test_not_yet_valid_certificate_refuses_the_request(self):
        self.assert_verification_failure(certificate='future')

    def test_socks_tunnel_keeps_real_tls_verification_and_encrypted_lookup(self):
        self.assertEqual(self.lookup(proxy=SocksProxy('127.0.0.1', 9050)).count, 12)
        tunnel = b''.join(self.tcp.sent)
        self.assertIn(b'service.leak-checker.invalid', tunnel)
        self.assertNotIn(HASH.encode(), tunnel)
        self.assertNotIn(b'GET ', tunnel)

    def test_socks_tunnel_does_not_weaken_hostname_verification(self):
        self.assert_verification_failure(proxy=SocksProxy('127.0.0.1', 9050),
                                         hostname='different.leak-checker.invalid')
