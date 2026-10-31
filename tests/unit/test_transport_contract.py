"""HTTP boundary tests with real header parsing and no sockets or DNS."""

from email.message import Message
from http.client import IncompleteRead
import io
import socket
import ssl
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

from passphrase_leak_checker.client import LeakCheckError, MODE_FULL_HASH, PwnedClient
from tests.support import ENDPOINT, HASH, OTHER, SUFFIX


class Response:
    def __init__(self, body, headers=None, status=200, error=None):
        self.body = body
        self.status = status
        self.headers = Message()
        for name, value in (headers if headers is not None else (
            ('Content-Type', 'text/plain; charset=utf-8'),
            ('Content-Length', str(len(body))),
        )):
            self.headers[name] = value
        self.error = error
        self.read_sizes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def read(self, size):
        self.read_sizes.append(size)
        if self.error:
            raise self.error
        return self.body[:size]


class TransportContractTests(unittest.TestCase):
    body = f'{SUFFIX}:12\r\n{OTHER}:0\r\n'.encode()

    def lookup(self, response, **options):
        client = PwnedClient(ENDPOINT, **options)
        opener = Mock()
        opener.open.return_value = response
        with patch('passphrase_leak_checker.client.build_opener', return_value=opener) as factory:
            result = client.check_secret('password')
        return result, opener, factory

    def test_matching_response_is_completely_read_and_closed(self):
        response = Response(self.body)
        result, opener, _ = self.lookup(response)
        self.assertEqual(result.count, 12)
        self.assertTrue(result.count_reported)
        self.assertEqual(response.read_sizes, [2 * 1024 * 1024 + 1])
        self.assertTrue(response.closed)
        opener.open.assert_called_once()

    def test_error_after_matching_row_never_becomes_a_match(self):
        response = Response(self.body + b'malformed\n')
        with self.assertRaises(LeakCheckError):
            self.lookup(response)
        self.assertTrue(response.closed)

    def test_every_non_200_status_is_unavailable_without_reading_body(self):
        for status in (100, 201, 202, 204, 206, 301, 302, 303, 307, 308,
                       400, 401, 403, 404, 408, 429, 500, 502, 503):
            with self.subTest(status=status):
                response = Response(self.body, status=status)
                with self.assertRaises(LeakCheckError):
                    self.lookup(response)
                self.assertEqual(response.read_sizes, [])
                self.assertTrue(response.closed)

    def test_http_errors_close_body_and_do_not_retry_or_expose_request(self):
        for status in (301, 302, 307, 308, 401, 403, 429, 500, 503):
            with self.subTest(status=status):
                body = io.BytesIO(b'private diagnostic')
                error = HTTPError('https://example.com/' + HASH, status, HASH, None, body)
                opener = Mock()
                opener.open.side_effect = error
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    with self.assertRaises(LeakCheckError) as raised:
                        PwnedClient(ENDPOINT).check_secret('password')
                self.assertTrue(body.closed)
                self.assertNotIn(HASH, str(raised.exception))
                self.assertNotIn('private diagnostic', str(raised.exception))
                opener.open.assert_called_once()

    def test_dns_tls_reset_and_timeout_failures_are_redacted(self):
        for error in (
            URLError(socket.gaierror('secret-diagnostic')),
            ssl.SSLCertVerificationError('secret-diagnostic'),
            ssl.SSLError('secret-diagnostic'),
            ConnectionResetError('secret-diagnostic'),
            TimeoutError('secret-diagnostic'),
        ):
            with self.subTest(error=type(error).__name__):
                opener = Mock()
                opener.open.side_effect = error
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    with self.assertRaises(LeakCheckError) as raised:
                        PwnedClient(ENDPOINT).check_secret('password')
                self.assertNotIn('secret-diagnostic', str(raised.exception))
                opener.open.assert_called_once()

    def test_missing_or_unexpected_content_type_is_unavailable(self):
        for content_type in (None, '', 'text/html', 'application/json',
                             'text/plain; charset=latin-1', 'text/plain; charset=utf-16'):
            with self.subTest(content_type=content_type):
                headers = [('Content-Length', str(len(self.body)))]
                if content_type is not None:
                    headers.append(('Content-Type', content_type))
                response = Response(self.body, headers)
                with self.assertRaises(LeakCheckError):
                    self.lookup(response)
                self.assertEqual(response.read_sizes, [])

    def test_duplicate_content_metadata_is_rejected(self):
        for duplicate in (
            [('Content-Type', 'text/plain'), ('Content-Type', 'text/html')],
            [('Content-Type', 'text/plain'), ('Content-Encoding', 'identity'),
             ('Content-Encoding', 'gzip')],
        ):
            with self.subTest(headers=duplicate), self.assertRaises(LeakCheckError):
                self.lookup(Response(self.body, duplicate + [('Content-Length', str(len(self.body)))]))

    def test_supported_ascii_and_utf8_content_types(self):
        for charset in ('ascii', 'us-ascii', 'UTF-8', 'utf8'):
            with self.subTest(charset=charset):
                response = Response(self.body, [('Content-Type', 'text/plain; charset=' + charset),
                                                ('Content-Length', str(len(self.body)))])
                self.assertTrue(self.lookup(response)[0].is_pwned)

    def test_compressed_or_unknown_encoding_is_rejected(self):
        for encoding in ('gzip', 'br', 'deflate', '', 'identity, gzip'):
            with self.subTest(encoding=encoding), self.assertRaises(LeakCheckError):
                self.lookup(Response(self.body, [('Content-Type', 'text/plain'),
                                                ('Content-Encoding', encoding),
                                                ('Content-Length', str(len(self.body)))]))

    def test_missing_length_or_chunked_framing_is_unavailable(self):
        response = Response(self.body, [('Content-Type', 'text/plain')])
        with self.assertRaises(LeakCheckError):
            self.lookup(response)
        self.assertEqual(response.read_sizes, [])

    def test_malformed_or_ambiguous_lengths_are_rejected(self):
        for framing in (
            [('Content-Length', value)] for value in ('', '-1', '+38', '1.0', '3e1', ' 38', '38,38')
        ):
            with self.subTest(framing=framing), self.assertRaises(LeakCheckError):
                self.lookup(Response(self.body, [('Content-Type', 'text/plain')] + framing))
        for framing in (
            [('Content-Length', '38'), ('Content-Length', '38')],
            [('Content-Length', '38'), ('Content-Length', '39')],
            [('Content-Length', '38'), ('Transfer-Encoding', 'chunked')],
            [('Transfer-Encoding', 'gzip')],
            [('Transfer-Encoding', 'chunked'), ('Transfer-Encoding', 'chunked')],
        ):
            with self.subTest(framing=framing), self.assertRaises(LeakCheckError):
                self.lookup(Response(self.body, [('Content-Type', 'text/plain')] + framing))

    def test_truncated_body_never_reports_a_result(self):
        response = Response(self.body, [('Content-Type', 'text/plain'),
                                        ('Content-Length', str(len(self.body) + 1))])
        with self.assertRaises(LeakCheckError):
            self.lookup(response)
        self.assertTrue(response.closed)

    def test_incomplete_chunk_error_closes_response(self):
        response = Response(self.body, [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')],
                            error=IncompleteRead(self.body, 20))
        with self.assertRaises(LeakCheckError):
            self.lookup(response)
        self.assertTrue(response.closed)

    def test_valid_decoded_chunked_body(self):
        response = Response(self.body, [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')])
        self.assertEqual(self.lookup(response)[0].count, 12)

    def test_advertised_oversize_body_is_not_read(self):
        response = Response(self.body)
        with self.assertRaises(LeakCheckError):
            self.lookup(response, max_response_bytes=len(self.body) - 1)
        self.assertEqual(response.read_sizes, [])

    def test_actual_size_limit_and_exact_boundary(self):
        response = Response(self.body, [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')])
        self.assertEqual(self.lookup(response, max_response_bytes=len(self.body))[0].count, 12)
        response = Response(self.body, [('Content-Type', 'text/plain'), ('Transfer-Encoding', 'chunked')])
        with self.assertRaises(LeakCheckError):
            self.lookup(response, max_response_bytes=len(self.body) - 1)
        self.assertEqual(response.read_sizes, [len(self.body)])

    def test_invalid_utf8_never_uses_replacement_decoding(self):
        with self.assertRaises(LeakCheckError):
            self.lookup(Response(self.body + b'\xff'))

    def test_full_hash_json_response_and_content_type(self):
        opener = Mock()
        opener.open.return_value = Response(b'{"count":12,"found":true}',
            [('Content-Type', 'application/json'), ('Content-Length', '25')])
        client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH, full_hash_consent=True)
        with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
            self.assertEqual(client.check_secret('password').count, 12)
        self.assertEqual(opener.open.call_args.args[0].full_url, 'https://example.com/' + HASH)

    def test_presence_only_responses_do_not_report_occurrence_counts(self):
        for body, present in ((b'true', True), (b'false', False), (b'{"found":true}', True),
                              (b'{"pwned":false}', False), (b'{"found":true,"pwned":true}', True)):
            with self.subTest(body=body):
                client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH, full_hash_consent=True)
                opener = Mock()
                opener.open.return_value = Response(body)
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    result = client.check_secret('public synthetic input')
                self.assertEqual(result.is_pwned, present)
                self.assertEqual(result.count, int(present))
                self.assertFalse(result.count_reported)

    def test_reported_occurrence_counts_include_numeric_one_and_zero(self):
        for body, count in ((b'1', 1), (b'0', 0), (b'{"count":1,"found":true}', 1),
                            (b'{"count":0,"found":false}', 0), (b'{"count":26230667}', 26230667)):
            with self.subTest(body=body):
                client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH, full_hash_consent=True)
                opener = Mock()
                opener.open.return_value = Response(body)
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    result = client.check_secret('public synthetic input')
                self.assertEqual(result.count, count)
                self.assertTrue(result.count_reported)

    def test_request_headers_timeout_direct_routing_and_verified_tls_defaults(self):
        _, opener, factory = self.lookup(Response(self.body), timeout_seconds=3,
                                         extra_headers={'Add-Padding': 'true'})
        request = opener.open.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(headers['accept-encoding'], 'identity')
        self.assertEqual(headers['add-padding'], 'true')
        self.assertTrue(headers['user-agent'].startswith('PassphraseLeakChecker/'))
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 3)
        self.assertEqual(request.full_url, ENDPOINT.replace('{prefix}', HASH[:5]))
        proxy = next(handler for handler in factory.call_args.args if isinstance(handler, ProxyHandler))
        self.assertEqual(proxy.proxies, {})
        actual_opener = build_opener(*factory.call_args.args)
        https = next(handler for handler in actual_opener.handlers if isinstance(handler, HTTPSHandler))
        context = https._context or ssl.create_default_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_redirect_handler_never_returns_a_forward_request(self):
        _, _, factory = self.lookup(Response(self.body))
        redirect = next(handler for handler in factory.call_args.args if hasattr(handler, 'redirect_request'))
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self.assertIsNone(redirect.redirect_request(None, None, code, '', {}, 'https://evil.example'))

    def test_policy_refusal_or_exception_prevents_open(self):
        for error in (LeakCheckError('offline'), RuntimeError('secret-diagnostic')):
            with self.subTest(error=type(error).__name__):
                guard = Mock(side_effect=error)
                opener = Mock()
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    with self.assertRaises(LeakCheckError) as raised:
                        PwnedClient(ENDPOINT, network_guard=guard).check_secret('password')
                guard.assert_called_once_with()
                opener.open.assert_not_called()
                self.assertNotIn('secret-diagnostic', str(raised.exception))

    def test_headers_are_revalidated_if_mutated_after_construction(self):
        client = PwnedClient(ENDPOINT)
        client.extra_headers['Host'] = 'evil.example'
        with patch('passphrase_leak_checker.client.build_opener') as factory, self.assertRaises(LeakCheckError):
            client.check_secret('password')
        factory.assert_not_called()
