"""Adversarial input, disclosure, and parser contracts; no network access."""

import itertools
import json
import unittest
from unittest.mock import patch

from passphrase_leak_checker.client import (
    LeakCheckError, LeakCheckOutcome, LeakCheckResult, MAX_COUNT,
    MAX_RESPONSE_BYTES, MODE_FULL_HASH, MODE_K_ANONYMITY, PwnedClient,
)
from tests.support import ENDPOINT, HASH, OTHER, SUFFIX


class ConfigurationBoundaryTests(unittest.TestCase):
    def test_timeout_and_size_reject_lossy_or_wrong_type_coercion(self):
        for name in ('timeout_seconds', 'max_response_bytes'):
            for value in (True, False, None, 1.5, float('nan'), float('inf'),
                          [], {}, '', '1.5', ' 7 ', '+7', '-1', '9' * 100):
                with self.subTest(name=name, value=repr(value)), self.assertRaises(LeakCheckError):
                    PwnedClient(ENDPOINT, **{name: value})

    def test_numeric_setting_limits(self):
        for value in (0, -1, 61):
            with self.subTest(timeout=value), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, timeout_seconds=value)
        for value in (0, -1, MAX_RESPONSE_BYTES + 1):
            with self.subTest(size=value), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, max_response_bytes=value)
        for timeout in (1, 60, '7'):
            for size in (1, MAX_RESPONSE_BYTES, '1024'):
                client = PwnedClient(ENDPOINT, timeout_seconds=timeout, max_response_bytes=size)
                self.assertEqual(client.timeout_seconds, int(timeout))
                self.assertEqual(client.max_response_bytes, int(size))

    def test_falsey_invalid_headers_are_not_silently_discarded(self):
        for value in ([], '', 0, False):
            with self.subTest(headers=value), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, extra_headers=value)

    def test_consent_is_an_explicit_boolean(self):
        for value in (1, 0, 'true', 'false', [], None):
            with self.subTest(consent=value), self.assertRaises(LeakCheckError):
                PwnedClient('https://example.com/{hash}', MODE_FULL_HASH, full_hash_consent=value)

    def test_guard_must_be_callable(self):
        for guard in (True, 0, 'direct', []):
            with self.subTest(guard=guard), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, network_guard=guard)

    def test_invalid_mode_and_endpoint_types_are_consistent_errors(self):
        for mode in (None, [], 0, '', 'K_ANONYMITY'):
            with self.subTest(mode=mode), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, mode=mode)
        for endpoint in (None, [], {}, 1, b'https://example.com/{prefix}', ''):
            with self.subTest(endpoint=endpoint), self.assertRaises(LeakCheckError):
                PwnedClient(endpoint)

    def test_every_reserved_header_is_case_insensitive(self):
        for name in ('host', 'accept-encoding', 'content-length', 'transfer-encoding',
                     'connection', 'proxy-authorization', 'proxy-connection'):
            for spelling in (name, name.upper(), name.title()):
                with self.subTest(header=spelling), self.assertRaises(LeakCheckError):
                    PwnedClient(ENDPOINT, extra_headers={spelling: 'value'})

    def test_header_names_values_and_duplicates(self):
        for headers in ({'': 'v'}, {'X Test': 'v'}, {'X:Test': 'v'}, {'X_Test': 'v'},
                        {'X-Test': None}, {'X-Test': ['value']}, {'X-Test': '\u2603'},
                        {'X-Test': 'a\x00b'}, {'X-Test': 'a\tb'}, {'X-Test': '\x7f'},
                        {'X-Test': 'one', 'x-test': 'two'}):
            with self.subTest(headers=headers), self.assertRaises(LeakCheckError):
                PwnedClient(ENDPOINT, extra_headers=headers)

    def test_valid_header_dictionary_is_copied(self):
        headers = {'Add-Padding': 'true'}
        client = PwnedClient(ENDPOINT, extra_headers=headers)
        headers['Host'] = 'evil.example'
        self.assertEqual(client.extra_headers, {'Add-Padding': 'true'})

    def test_destination_mutation_requires_fresh_full_hash_approval(self):
        client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH, full_hash_consent=True)
        client.endpoint_template = 'https://other.example/{hash}'
        with patch.object(client, '_http_get') as request, self.assertRaises(LeakCheckError):
            client.check_secret('password')
        request.assert_not_called()


class ParserBoundaryTests(unittest.TestCase):
    def test_range_count_boundaries_and_zero_padding(self):
        for count in (0, 1, MAX_COUNT):
            for ending in ('', '\n', '\r\n'):
                with self.subTest(count=count, ending=repr(ending)):
                    self.assertEqual(PwnedClient._parse_k_anonymity_response(
                        f'{OTHER}:0\r\n{SUFFIX.lower()}:{count}' + ending, SUFFIX), count)

    def test_range_rejects_non_ascii_digits_spaces_and_extra_separators(self):
        for count in ('\u0661', '\uff11', '+1', '-0', '1 ', ' 1', '1_000', '1e3', '1:0'):
            with self.subTest(count=count), self.assertRaises(LeakCheckError):
                PwnedClient._parse_k_anonymity_response(f'{SUFFIX}:{count}', SUFFIX)
        for row in (f' {SUFFIX}:1', f'{SUFFIX}:1 ', f'{SUFFIX}:1\r', f'{SUFFIX}:1\n\n',
                    f'{SUFFIX}:1\x00', f'{SUFFIX}:1\u2028{OTHER}:0'):
            with self.subTest(row=repr(row)), self.assertRaises(LeakCheckError):
                PwnedClient._parse_k_anonymity_response(row, SUFFIX)

    def test_range_order_does_not_change_match_count(self):
        rows = (f'{SUFFIX}:17', f'{OTHER}:0', f'{"F" * 35}:4')
        for order in itertools.permutations(rows):
            with self.subTest(order=order):
                self.assertEqual(PwnedClient._parse_k_anonymity_response('\n'.join(order), SUFFIX), 17)

    def test_corruption_before_or_after_match_always_fails(self):
        valid = f'{SUFFIX}:17'
        for bad in ('invalid', f'{OTHER}:-1', f'{OTHER}:{MAX_COUNT + 1}', '', f'{SUFFIX.lower()}:0'):
            for rows in ((valid, bad), (bad, valid)):
                with self.subTest(rows=rows), self.assertRaises(LeakCheckError):
                    PwnedClient._parse_k_anonymity_response('\n'.join(rows) + '\n', SUFFIX)

    def test_all_count_and_flag_agreements(self):
        for count, found, pwned in itertools.product((0, 1, MAX_COUNT), (None, False, True), (None, False, True)):
            payload = {'count': count}
            payload.update({name: value for name, value in (('found', found), ('pwned', pwned))
                            if value is not None})
            consistent = all(value is None or value == (count > 0) for value in (found, pwned))
            with self.subTest(payload=payload):
                if consistent:
                    self.assertEqual(PwnedClient._parse_full_hash_response(json.dumps(payload), HASH),
                                     (count, True))
                else:
                    with self.assertRaises(LeakCheckError):
                        PwnedClient._parse_full_hash_response(json.dumps(payload), HASH)

    def test_wrong_count_and_flag_types(self):
        for value in (None, True, False, -1, 1.0, '1', [], {}, MAX_COUNT + 1):
            with self.subTest(count=value), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(json.dumps({'count': value}), HASH)
        for name, value in itertools.product(('found', 'pwned'), (None, 0, 1, 'true', [], {})):
            with self.subTest(name=name, flag=value), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(json.dumps({name: value}), HASH)

    def test_duplicate_hash_flag_and_count_keys_are_rejected(self):
        for body in ('{"found":false,"found":true}', '{"pwned":false,"pwned":false}',
                     '{"count":0,"count":0}', '{"count":0,"hash":"' + HASH + '","hash":"' + HASH + '"}'):
            with self.subTest(body=body), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(body, HASH)

    def test_nonfinite_nested_or_trailing_json_is_unavailable(self):
        for body in ('NaN', 'Infinity', '-Infinity', '1e999', '{"count":NaN}',
                     '{"found":{"found":true}}', '{"count":0}{}', '0\x00', 'true false',
                     '\ufeff0', '[' * 1100 + '0' + ']' * 1100):
            with self.subTest(body=body[:40]), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(body, HASH)

    def test_response_hash_must_belong_to_this_lookup(self):
        for value in (None, [], 1, HASH[:39], 'G' * 40, 'F' * 40):
            with self.subTest(hash=value), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(json.dumps({'count': 1, 'hash': value}), HASH)

    def test_result_repr_excludes_full_hash(self):
        result = LeakCheckResult(True, 1, HASH, MODE_K_ANONYMITY)
        self.assertNotIn(HASH, repr(result))
        self.assertNotIn(SUFFIX, repr(result))
        self.assertEqual(result.outcome, LeakCheckOutcome.MATCH)

    def test_result_consistency_and_frozen_fields(self):
        for is_pwned, count in ((False, 1), (True, 0), (1, 1), (False, True), (True, -1), (True, MAX_COUNT + 1)):
            with self.subTest(is_pwned=is_pwned, count=count), self.assertRaises(LeakCheckError):
                LeakCheckResult(is_pwned, count, HASH, MODE_K_ANONYMITY)
        result = LeakCheckResult(False, 0, HASH, MODE_K_ANONYMITY)
        with self.assertRaises(AttributeError):
            result.count = 1
        for reported in (None, 0, 1, 'true'):
            with self.subTest(count_reported=reported), self.assertRaises(LeakCheckError):
                LeakCheckResult(True, 1, HASH, MODE_K_ANONYMITY, count_reported=reported)
        with self.assertRaises(LeakCheckError):
            LeakCheckResult(True, 2, HASH, MODE_K_ANONYMITY, count_reported=False)


class URLBoundaryTests(unittest.TestCase):
    def test_alternate_loopback_spellings_do_not_enable_http(self):
        for host in ('localhost', 'localhost.', '127.1', '2130706433', '0177.0.0.1',
                     '0x7f000001', '127.0.0.1.evil.example', 'example.com', '10.0.0.1'):
            with self.subTest(host=host), self.assertRaises(LeakCheckError):
                PwnedClient('http://' + host + '/{prefix}')

    def test_control_characters_and_encoded_controls_are_rejected(self):
        for code in (*range(32), 127):
            for suffix in (chr(code), f'%{code:02x}'):
                with self.subTest(code=code, encoded=suffix.startswith('%')), self.assertRaises(LeakCheckError):
                    PwnedClient(ENDPOINT + suffix)

    def test_onion_userinfo_bad_labels_and_unicode_authorities_are_rejected(self):
        for host in ('hidden.onion', 'HIDDEN.ONION.', 'user@example.com', 'user:pw@example.com',
                     '-bad.example', 'bad-.example', 'bad..example', 'a' * 64 + '.example',
                     '\u00e9xample.com', 'example.com%2f@evil.example'):
            with self.subTest(host=host), self.assertRaises(LeakCheckError):
                PwnedClient('https://' + host + '/{prefix}')

    def test_range_template_substitution_never_includes_suffix_or_full_hash(self):
        for template in ('https://example.com/{prefix}', 'https://example.com/?p={prefix}',
                         'https://example.com/{prefix}?again={prefix}'):
            client = PwnedClient(template)
            url = client._build_url(HASH[:5], SUFFIX, HASH)
            self.assertNotIn(SUFFIX, url)
            self.assertNotIn(HASH, url)
            self.assertEqual(client.destination, 'https://example.com')
