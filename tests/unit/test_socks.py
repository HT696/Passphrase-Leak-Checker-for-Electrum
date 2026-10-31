"""SOCKS wire negotiation through memory sockets, never real DNS or sockets."""

import io
import socket
from threading import Event
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import LeakCheckError, PwnedClient, SocksProxy, _RequestBudget
from tests.support import HASH, OTHER, SUFFIX
from tests.unit.test_request_budget import MemorySocket


SOCKS5_OK = b'\x05\x00\x05\x00\x00\x01' + b'\x00' * 6


class SocksSocket(MemorySocket):
    def __init__(self, replies=SOCKS5_OK, wire=None, fragment=1):
        super().__init__(io.BytesIO() if wire is None else wire)
        self.replies = io.BytesIO(replies)
        self.fragment = fragment

    def recv(self, size):
        return self.replies.read(min(size, self.fragment))


class SocksConfigurationTests(unittest.TestCase):
    def test_invalid_proxy_fields_are_refused(self):
        for options in (
            {'host': ''}, {'host': None}, {'host': 'example.invalid/path'},
            {'host': 'user@example.invalid'}, {'host': 'example.invalid#fragment'},
            {'host': 'example.invalid?query'}, {'host': 'example.invalid\n'},
            {'host': 'example.invalid:443'}, {'mode': 'http'}, {'mode': None},
            {'port': True}, {'port': '9050'}, {'port': 0}, {'port': 65536},
            {'username': True}, {'password': []}, {'username': 'u\x00x'},
            {'username': '\ud800'}, {'username': 'x' * 256},
            {'username': 'user'}, {'password': 'password'},
            {'mode': 'socks4', 'username': 'user', 'password': 'password'},
        ):
            with self.subTest(options=options), self.assertRaises(LeakCheckError):
                SocksProxy(**dict({'host': '127.0.0.1', 'port': 9050}, **options))

    def test_proxy_snapshot_is_frozen_and_repr_omits_credentials(self):
        proxy = SocksProxy('::1', 9050, username='private-user', password='private-password')
        self.assertNotIn('private-', repr(proxy))
        with self.assertRaises(AttributeError):
            proxy.host = 'example.invalid'

    def test_empty_credentials_normalize_to_anonymous(self):
        self.assertEqual(SocksProxy('127.0.0.1', 9050, username='', password=''),
                         SocksProxy('127.0.0.1', 9050))

    def test_client_rejects_implicit_proxy_values(self):
        for value in (False, '', {}, 'socks5://127.0.0.1:9050'):
            with self.subTest(value=value), self.assertRaises(LeakCheckError):
                PwnedClient('https://example.invalid/{prefix}', proxy=value)


class SocksNegotiationTests(unittest.TestCase):
    def connect(self, sock, proxy=None, target=('service.example.invalid', 443)):
        proxy = SocksProxy('127.0.0.1', 9050) if proxy is None else proxy
        budget = _RequestBudget(7, Event(), proxy=proxy)
        try:
            with patch('passphrase_leak_checker.client.socket.socket', return_value=sock) as factory, \
                    patch('passphrase_leak_checker.client.socket.getaddrinfo') as dns:
                self.assertIs(budget.connect(target), sock)
                self.assertEqual(sock.target, (proxy.host, proxy.port))
                dns.assert_not_called()
                factory.assert_called_once()
        finally:
            budget.close()
        return b''.join(sock.sent)

    def test_socks5_uses_remote_dns_and_consumes_fragmented_reply(self):
        sock = SocksSocket()
        sent = self.connect(sock)
        host = b'service.example.invalid'
        self.assertEqual(sent, b'\x05\x01\x00\x05\x01\x00\x03' + bytes((len(host),)) + host + b'\x01\xbb')
        self.assertEqual(sock.replies.read(), b'')
        self.assertTrue(sock.closed)

    def test_socks5_authentication_uses_only_the_configured_credentials(self):
        proxy = SocksProxy('127.0.0.1', 9050, username='public-user', password='public-password')
        sock = SocksSocket(b'\x05\x02\x01\x00' + SOCKS5_OK[2:])
        sent = self.connect(sock, proxy)
        self.assertTrue(sent.startswith(b'\x05\x01\x02\x01\x0bpublic-user\x0fpublic-password'))

    def test_socks5_encodes_ipv4_and_ipv6_without_dns(self):
        for host, kind, size in (('192.0.2.1', 1, 4), ('2001:db8::1', 4, 16)):
            with self.subTest(host=host):
                sent = self.connect(SocksSocket(), target=(host, 443))
                self.assertEqual(sent[6], kind)
                self.assertEqual(len(sent[7:-2]), size)

    def test_socks5_accepts_all_valid_bound_address_types(self):
        for address in (b'\x01' + b'\x00' * 4, b'\x04' + b'\x00' * 16,
                        b'\x03\x03foo'):
            with self.subTest(address=address):
                self.connect(SocksSocket(b'\x05\x00\x05\x00\x00' + address + b'\x00\x00'))

    def test_socks5_rejects_bad_versions_methods_statuses_and_truncation(self):
        replies = (b'', b'\x05', b'\x04\x00', b'\x05\xff', b'\x05\x02',
                   b'\x05\x00\x04\x00\x00\x01', b'\x05\x00\x05\x01\x00\x01',
                   b'\x05\x00\x05\x00\x01\x01', b'\x05\x00\x05\x00\x00\x09',
                   b'\x05\x00\x05\x00\x00\x03\x00', SOCKS5_OK[:-1])
        for reply in replies:
            with self.subTest(reply=reply), self.assertRaises(LeakCheckError):
                sock = SocksSocket(reply)
                self.connect(sock)
            self.assertTrue(sock.closed)

    def test_authentication_failure_does_not_send_a_connect_or_http_request(self):
        proxy = SocksProxy('127.0.0.1', 9050, username='public-user', password='public-password')
        for response in (b'\x05\x00', b'\x05\x02\x01\x01', b'\x05\x02\x02\x00'):
            with self.subTest(response=response), self.assertRaises(LeakCheckError):
                sock = SocksSocket(response)
                self.connect(sock, proxy)
            sent = b''.join(sock.sent)
            self.assertNotIn(b'service.example.invalid', sent)
            self.assertNotIn(b'GET ', sent)

    def test_socks4a_sends_hostname_to_proxy_without_local_resolution(self):
        sock = SocksSocket(b'\x00\x5a' + b'\x00' * 6)
        proxy = SocksProxy('127.0.0.1', 9050, mode='socks4', username='public-user')
        self.assertEqual(self.connect(sock, proxy),
                         b'\x04\x01\x01\xbb\x00\x00\x00\x01public-user\x00service.example.invalid\x00')

    def test_socks4_ipv4_is_encoded_without_a_domain_suffix(self):
        sock = SocksSocket(b'\x00\x5a' + b'\x00' * 6)
        sent = self.connect(sock, SocksProxy('127.0.0.1', 9050, mode='socks4'), target=('192.0.2.1', 443))
        self.assertEqual(sent, b'\x04\x01\x01\xbb\xc0\x00\x02\x01\x00')

    def test_socks4_rejects_ipv6_before_opening_a_socket(self):
        budget = _RequestBudget(7, Event(), proxy=SocksProxy('127.0.0.1', 9050, mode='socks4'))
        with patch('passphrase_leak_checker.client.socket.socket') as factory, self.assertRaises(LeakCheckError):
            budget.connect(('::1', 443))
        factory.assert_not_called()

    def test_socks4_failure_and_truncation_never_fall_back_to_direct(self):
        for reply in (b'', b'\x00\x5a', b'\x04\x5a' + b'\x00' * 6,
                      b'\x00\x5b' + b'\x00' * 6):
            with self.subTest(reply=reply), self.assertRaises(LeakCheckError):
                sock = SocksSocket(reply)
                self.connect(sock, SocksProxy('127.0.0.1', 9050, mode='socks4'))
            self.assertNotIn(b'GET ', b''.join(sock.sent))

    def test_https_lookup_over_socks_uses_the_real_http_parser(self):
        body = (OTHER + ':0\n').encode()
        wire = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ' +
                          str(len(body)).encode() + b'\r\n\r\n' + body)
        sock = SocksSocket(wire=wire)
        client = PwnedClient('https://127.0.0.2/range/{prefix}', proxy=SocksProxy('127.0.0.1', 9050))
        with patch('passphrase_leak_checker.client.socket.socket', return_value=sock) as factory, \
                patch('passphrase_leak_checker.client.socket.getaddrinfo') as dns, \
                patch('ssl.SSLContext.wrap_socket', return_value=sock):
            self.assertFalse(client.check_secret('password').is_pwned)
        factory.assert_called_once()
        dns.assert_not_called()
        self.assertEqual(sock.target, ('127.0.0.1', 9050))
        sent = b''.join(sock.sent)
        self.assertIn(('GET /range/' + HASH[:5]).encode(), sent)
        self.assertNotIn(HASH.encode(), sent)
        self.assertNotIn(SUFFIX.encode(), sent)

    def test_http_is_refused_with_any_proxy_before_io_including_full_hash(self):
        for host in ('127.0.0.1', '198.51.100.7', '::1'):
            for mode, field in (('k_anonymity', 'prefix'), ('full_hash', 'hash')):
                with self.subTest(host=host, mode=mode), \
                        patch('passphrase_leak_checker.client.socket.socket') as factory, self.assertRaises(LeakCheckError):
                    PwnedClient('http://127.0.0.1/{' + field + '}', mode,
                                proxy=SocksProxy(host, 9050), full_hash_consent=True)
                factory.assert_not_called()

    def test_failed_proxy_connection_never_attempts_the_destination(self):
        sock = SocksSocket()
        sock.connect = Mock(side_effect=ConnectionRefusedError('public diagnostic'))
        client = PwnedClient('https://service.example.invalid/{prefix}', proxy=SocksProxy('127.0.0.1', 9050))
        with patch('passphrase_leak_checker.client.socket.socket', return_value=sock) as factory, \
                patch('passphrase_leak_checker.client.socket.getaddrinfo') as dns, self.assertRaises(LeakCheckError):
            client.check_secret('password')
        factory.assert_called_once()
        sock.connect.assert_called_once_with(('127.0.0.1', 9050))
        dns.assert_not_called()
        self.assertEqual(sock.sent, [])

    def test_slow_proxy_reads_share_the_total_deadline(self):
        clock = [0.0]
        sock = SocksSocket()
        recv = sock.recv
        def slow(size):
            clock[0] += 0.3
            return recv(size)
        sock.recv = slow
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            budget = _RequestBudget(1, Event(), proxy=SocksProxy('127.0.0.1', 9050))
            with patch('passphrase_leak_checker.client.socket.socket', return_value=sock), self.assertRaises(TimeoutError):
                budget.connect(('service.example.invalid', 443))
            budget.close()
        self.assertLessEqual(clock[0], 1.21)
        self.assertTrue(sock.closed)

    def test_named_proxy_resolution_cannot_resolve_the_destination(self):
        sock = SocksSocket()
        proxy = SocksProxy('proxy.example.invalid', 9050)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.0.2.1', 9050))]
        budget = _RequestBudget(7, Event(), proxy=proxy)
        with patch('passphrase_leak_checker.client._resolve_host', return_value=addresses) as resolve, \
                patch('passphrase_leak_checker.client.socket.socket', return_value=sock):
            budget.connect(('service.example.invalid', 443))
        self.assertEqual(resolve.call_args_list[0].args[:2], ('proxy.example.invalid', 9050))
        resolve.assert_called_once()
        self.assertEqual(sock.target, ('192.0.2.1', 9050))
        budget.close()

    def test_partial_proxy_writes_share_the_total_deadline(self):
        clock = [0.0]
        sock = SocksSocket()
        def slow_send(data):
            clock[0] += 0.3
            return 1
        sock.send = slow_send
        with patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            budget = _RequestBudget(1, Event(), proxy=SocksProxy('127.0.0.1', 9050))
            with patch('passphrase_leak_checker.client.socket.socket', return_value=sock), self.assertRaises(TimeoutError):
                budget.connect(('service.example.invalid', 443))
            budget.close()
        self.assertLessEqual(clock[0], 1.21)

    def test_cancel_during_proxy_negotiation_closes_socket_and_sends_no_http(self):
        sock = SocksSocket()
        client = PwnedClient('https://service.example.invalid/{prefix}', proxy=SocksProxy('127.0.0.1', 9050))
        def cancel(size):
            client.cancel()
            return b'\x05'
        sock.recv = cancel
        with patch('passphrase_leak_checker.client.socket.socket', return_value=sock), self.assertRaises(LeakCheckError):
            client.check_secret('password')
        self.assertTrue(sock.closed)
        self.assertNotIn(b'GET ', b''.join(sock.sent))
