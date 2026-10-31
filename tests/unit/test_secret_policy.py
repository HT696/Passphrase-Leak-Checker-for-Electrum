"""Verify delegation to host rules; no copied normalization or seed wordlists."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.electrum.secret_policy import prepare_secret
from passphrase_leak_checker.client import LeakCheckError


class SecretPolicyTests(unittest.TestCase):
    def setUp(self):
        self.native = Mock(return_value='password')
        self.bip39 = Mock(return_value='cafe\u0301')
        self.is_seed = Mock(return_value=False)
        self.checksum = Mock(return_value=(False, False))
        self.decode = Mock(side_effect=ValueError)
        self.modules = patch.dict('sys.modules', {
            'electrum.mnemonic': SimpleNamespace(normalize_text=self.native, is_seed=self.is_seed),
            'electrum.keystore': SimpleNamespace(bip39_normalize_passphrase=self.bip39,
                                                 bip39_is_checksum_valid=self.checksum),
            'electrum.slip39': SimpleNamespace(decode_mnemonic=self.decode, Slip39Error=ValueError),
        })
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_native_extensions_use_host_normalization_for_each_seed_type(self):
        for kind in ('standard', 'segwit', '2fa', '2fa_segwit', 'electrum'):
            with self.subTest(kind=kind):
                value, description = prepare_secret('  PASSWORD  ', kind)
                self.assertEqual(value, 'password')
                self.assertIn('Electrum-normalized', description)
                self.native.assert_called_with('  PASSWORD  ')
        self.bip39.assert_not_called()

    def test_bip39_uses_host_rule_without_native_case_or_space_changes(self):
        self.assertEqual(prepare_secret('café', 'bip39')[0], 'cafe\u0301')
        self.bip39.assert_called_once_with('café')
        self.native.assert_not_called()

    def test_wallet_passwords_and_slip39_retain_exact_text(self):
        for kind in (None, 'slip39'):
            self.assertEqual(prepare_secret('  PASSWORD café  ', kind)[0], '  PASSWORD café  ')
        self.native.assert_not_called()
        self.bip39.assert_not_called()

    def test_unknown_extension_and_empty_effective_values_are_refused(self):
        for kind in ('unknown', 'old', 'new_future_seed_format'):
            with self.assertRaises(LeakCheckError):
                prepare_secret('public extension', kind)
        self.native.return_value = ''
        with self.assertRaises(LeakCheckError):
            prepare_secret('   ', 'segwit')

    def test_recognized_native_bip39_and_slip39_mnemonics_are_refused_locally(self):
        for family, count in (('native', 12), ('bip39', 12), ('slip39', 20)):
            self.is_seed.return_value = family == 'native'
            self.checksum.return_value = (family == 'bip39', family == 'bip39')
            self.decode.side_effect = None if family == 'slip39' else ValueError
            with self.subTest(family=family), self.assertRaisesRegex(LeakCheckError, 'recovery-seed'):
                prepare_secret(' '.join(['public'] * count))

    def test_hexadecimal_recovery_seed_is_checked_with_host_validator(self):
        self.is_seed.return_value = True
        with self.assertRaisesRegex(LeakCheckError, 'recovery-seed'):
            prepare_secret('a' * 32)
        self.is_seed.assert_called_once_with('a' * 32)

    def test_unknown_multiword_phrase_is_not_mislabelled_as_a_known_seed(self):
        text = ' '.join(['public'] * 12)
        self.assertEqual(prepare_secret(text)[0], text)
        self.is_seed.assert_called_once_with(text)
        self.checksum.assert_called_once_with(text)

    def test_failed_host_validation_or_normalization_refuses_the_check(self):
        for failure in (ImportError, RuntimeError):
            self.native.side_effect = failure('sensitive diagnostic')
            with self.assertRaises(LeakCheckError) as raised:
                prepare_secret('public phrase', 'segwit')
            self.assertNotIn('sensitive diagnostic', str(raised.exception))
