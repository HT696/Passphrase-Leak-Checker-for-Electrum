import json
import unittest
from unittest.mock import patch

from passphrase_leak_checker.client import (
    LeakCheckError, LeakCheckOutcome, LeakCheckResult, MAX_COUNT,
    MODE_FULL_HASH, MODE_K_ANONYMITY, PwnedClient, lookup_outcome,
)
from tests.support import HASH, SUFFIX, OTHER, ENDPOINT


class SecretInputTests(unittest.TestCase):
    def test_invalid_input_never_starts_a_request(self):
        client = PwnedClient(ENDPOINT)
        for secret in ('', None, b'password', 0, '\ud800'):
            with self.subTest(secret=repr(secret)), patch.object(client, '_http_get') as request:
                with self.assertRaises(LeakCheckError):
                    client.check_secret(secret)
                request.assert_not_called()

    def test_password_case_and_whitespace_are_preserved(self):
        client = PwnedClient(ENDPOINT)
        with patch.object(client, '_http_get', return_value=f'{SUFFIX}:12\n') as request:
            self.assertTrue(client.check_secret('password').is_pwned)
            for secret in ('Password', ' password', 'password ', 'pass word'):
                with self.subTest(secret=secret):
                    self.assertEqual(client.check_secret(secret).outcome, LeakCheckOutcome.NO_MATCH)
                    self.assertNotEqual(request.call_args.args[0], ENDPOINT.replace('{prefix}', HASH[:5]))

    def test_unicode_is_utf8_without_normalization(self):
        expected_hash = '37EAB091D1180D22974557AA424264B9B3DF8E38'
        client = PwnedClient(ENDPOINT, include_hash=True)
        with patch.object(client, '_http_get', return_value=f'{expected_hash[5:]}:12\n') as request:
            result = client.check_secret('café 🔑')
            self.assertEqual(result.sha1_hash, expected_hash)
            self.assertTrue(result.is_pwned)
            self.assertEqual(request.call_args.args[0], ENDPOINT.replace('{prefix}', expected_hash[:5]))
            # Visually identical text with a decomposed accent is a different lookup.
            self.assertEqual(client.check_secret('cafe\u0301 🔑').outcome, LeakCheckOutcome.NO_MATCH)

    def test_hash_is_absent_from_results_unless_explicitly_requested(self):
        for enabled in (False, True):
            client = PwnedClient(ENDPOINT, include_hash=enabled)
            with patch.object(client, '_http_get', return_value=f'{SUFFIX}:12\n'):
                result = client.check_secret('password')
            self.assertEqual(result.sha1_hash, HASH if enabled else None)
            self.assertNotIn(HASH, repr(result))
        for invalid in (None, 'true', 1):
            with self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, include_hash=invalid)


class ResponseTests(unittest.TestCase):
    def test_valid_range_and_padding(self):
        parse = PwnedClient._parse_k_anonymity_response
        self.assertEqual(parse(f'{OTHER}:0\r\n{SUFFIX.lower()}:12\r\n', SUFFIX), 12)
        self.assertEqual(parse(f'{OTHER}:5\n', SUFFIX), 0)
        self.assertEqual(parse(f'{SUFFIX}:0', SUFFIX), 0)

    def test_invalid_ranges_never_mean_no_match(self):
        for body in ('', '\n', '<html>unavailable</html>', '{"error":"unavailable"}',
                     f'{SUFFIX}:-1', f'{SUFFIX}:1.5', f'{SUFFIX}:true',
                     f'{SUFFIX}:1\ninvalid', f'{OTHER}:bad\n{SUFFIX}:1',
                     f'{SUFFIX}:0\n{SUFFIX}:1', f'{SUFFIX}:1\n{SUFFIX.lower()}:1',
                     f'{OTHER}:0\n\n', f'{SUFFIX}:', f'{SUFFIX}:{MAX_COUNT + 1}'):
            with self.subTest(body=body), self.assertRaises(LeakCheckError):
                PwnedClient._parse_k_anonymity_response(body, SUFFIX)

    def test_valid_full_hash_responses(self):
        for payload, expected in [(True, (1, False)), (False, (0, False)), (12, (12, True)), (0, (0, True)),
                                  ({'count': 12, 'found': True, 'hash': HASH.lower()}, (12, True)),
                                  ({'pwned': False}, (0, False)),
                                  ({'found': True, 'pwned': True}, (1, False))]:
            with self.subTest(payload=payload):
                self.assertEqual(PwnedClient._parse_full_hash_response(json.dumps(payload), HASH), expected)

    def test_invalid_full_hash_responses(self):
        for body in ('', ' ', '-1', 'null', '[]', '1.5', 'NaN', 'clean', '"0"',
                     '{}', '{"count":0', '{"count":0,"found":true}',
                     '{"found":false,"pwned":true}', '{"count":true}',
                     '{"count":"0"}', '{"found":"false"}', '{"count":0,"error":"bad"}',
                     '{"count":0,"count":1}', '{"count":0,"hash":"wrong"}',
                     json.dumps({'count': 0, 'hash': 'A' * 40}), str(MAX_COUNT + 1)):
            with self.subTest(body=body), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(body, HASH)

    def test_ui_outcome_requires_valid_result(self):
        clean = LeakCheckResult(False, 0, HASH, MODE_K_ANONYMITY)
        match = LeakCheckResult(True, 3, HASH, MODE_K_ANONYMITY)
        self.assertEqual(lookup_outcome(clean, None), LeakCheckOutcome.NO_MATCH)
        self.assertEqual(lookup_outcome(match, None), LeakCheckOutcome.MATCH)
        for result, error in [(None, None), (None, ''), (clean, 'bad'), (object(), None), (match, '')]:
            self.assertEqual(lookup_outcome(result, error), LeakCheckOutcome.UNAVAILABLE)
        with self.assertRaises(LeakCheckError):
            LeakCheckResult(False, 1, HASH, MODE_K_ANONYMITY)


class TemplateTests(unittest.TestCase):
    def test_k_anonymity_rejects_disclosure(self):
        for template in ('https://example.com/{hash}',
                         'https://example.com/{prefix}?suffix={suffix}',
                         'https://example.com/{suffix}', 'https://example.com/static'):
            with self.subTest(template=template), self.assertRaises(LeakCheckError):
                PwnedClient(template)

    def test_rejects_unsafe_templates_in_both_modes(self):
        templates = (
            'https://{hash[0]}.example.com/{prefix}', 'https://{prefix}.example.com/{prefix}',
            'https://example.com/{prefix[0]}', 'https://example.com/{prefix!s}',
            'https://example.com/{prefix:5}', 'https://example.com/{prefix:}',
            'https://example.com/{prefix.__class__}', 'https://example.com/{{prefix}}',
            'https://example.com/{unknown}', '{prefix}://example.com/{prefix}',
            'https://user:pass@example.com/{prefix}', 'https://example.com/{prefix}#fragment',
            'https://example.com/{prefix}#', 'https://example.com:bad/{prefix}',
            'https://example.com:0/{prefix}', 'https://example.com:65536/{prefix}',
            'https://example.com:/{prefix}', 'https://[::1/{prefix}',
            'https://[::1]evil/{prefix}', 'https://[v1.a]/{prefix}',
            'https://example.com/\n{prefix}', 'https://example.com/%0d{prefix}',
            'https://example.com\\@evil.com/{prefix}', 'https://exa%6dple.com/{prefix}',
            'https://example..com/{prefix}', 'https://service.onion/{prefix}',
            'file:///tmp/{prefix}', 'https:///range/{prefix}',
        )
        for template in templates:
            for mode in (MODE_K_ANONYMITY, MODE_FULL_HASH):
                candidate = template if mode == MODE_K_ANONYMITY else template.replace('{prefix}', '{hash}')
                with self.subTest(template=candidate, mode=mode), self.assertRaises(LeakCheckError):
                    PwnedClient(candidate, mode=mode)

    def test_valid_templates(self):
        for template in (ENDPOINT, 'https://example.com:443/check?p={prefix}',
                         'http://127.0.0.1:8787/{prefix}', 'http://[::1]:8787/{prefix}'):
            client = PwnedClient(template)
            self.assertEqual(client._build_url(HASH[:5], SUFFIX, HASH), template.replace('{prefix}', HASH[:5]))
        for template in ('https://example.com/{hash}', 'https://example.com/?p={prefix}&s={suffix}'):
            client = PwnedClient(template, MODE_FULL_HASH)
            self.assertNotIn('{', client._build_url(HASH[:5], SUFFIX, HASH))

    def test_remote_http_is_rejected(self):
        for host in ('example.com', 'localhost', '192.168.0.1', '127.0.0.1.example.com'):
            with self.subTest(host=host), self.assertRaises(LeakCheckError):
                PwnedClient(f'http://{host}/{{prefix}}')

    def test_consent_is_required_and_bound_to_destination(self):
        client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH)
        with patch.object(client, '_http_get', return_value='0') as request:
            with self.assertRaises(LeakCheckError):
                client.check_secret('password')
            request.assert_not_called()
            with self.assertRaises(LeakCheckError):
                client.approve_full_hash_disclosure('https://other.com')
            client.approve_full_hash_disclosure(client.destination)
            self.assertFalse(client.check_secret('password').is_pwned)
            client.endpoint_template = 'https://other.com/{hash}'
            with self.assertRaises(LeakCheckError):
                client.check_secret('password')
            self.assertEqual(request.call_count, 1)

    def test_actual_range_request_contains_only_prefix(self):
        client = PwnedClient(ENDPOINT)
        with patch.object(client, '_http_get', return_value=f'{OTHER}:0\n') as request:
            client.check_secret('password')
        self.assertEqual(request.call_args.args[0], 'https://example.com/range/' + HASH[:5])
        self.assertNotIn(SUFFIX, request.call_args.args[0])

    def test_reserved_and_injected_headers(self):
        for headers in ({'Host': 'evil.com'}, {'X-Test': 'ok\r\nInjected: true'},
                        {'Accept-Encoding': 'gzip'}, {'Proxy-Authorization': 'secret'},
                        {'X-Test': 'a', 'x-test': 'b'}, {'X-Test': 1}):
            with self.subTest(headers=headers), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, extra_headers=headers)
