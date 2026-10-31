"""Qt handler tests with host stubs; not a full Electrum integration test."""
import importlib
import importlib.util
import sys
import types
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import (
    LeakCheckError, LeakCheckResult, MODE_FULL_HASH, MODE_K_ANONYMITY, PwnedClient, SocksProxy,
)

QT_AVAILABLE = bool(importlib.util.find_spec('PyQt6') or importlib.util.find_spec('PyQt5'))

@unittest.skipUnless(QT_AVAILABLE,
                     'Qt binding unavailable; install via the supported Electrum environment')
class PluginUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        modules = {name: types.ModuleType(name) for name in (
            'electrum', 'electrum.i18n', 'electrum.plugin', 'electrum.gui',
            'electrum.gui.qt', 'electrum.gui.qt.util')}
        modules['electrum.i18n']._ = lambda text: text
        modules['electrum.plugin'].BasePlugin = object
        modules['electrum.plugin'].hook = lambda method: method
        for name in ('Buttons', 'CancelButton', 'EnterButton', 'OkButton', 'WindowModalDialog'):
            setattr(modules['electrum.gui.qt.util'], name, Mock())
        with patch.dict(sys.modules, modules):
            cls.qt = importlib.import_module('passphrase_leak_checker.electrum.qt')

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.parent = Mock()
        self.button = Mock()
        self.button.window.return_value = self.parent

    def tearDown(self):
        self.plugin.close()

    def test_missing_result_and_error_are_unavailable(self):
        with patch.object(self.qt.QMessageBox, 'warning') as warning, \
                patch.object(self.qt.QMessageBox, 'information') as information:
            self.plugin._on_async_check_finished(self.parent, self.button, None, None, None, None)
            warning.assert_called_once()
            information.assert_not_called()
            self.assertIn('Could not check for leaks', warning.call_args.args[2])

    def test_only_valid_negative_result_shows_no_match(self):
        clean = LeakCheckResult(False, 0, 'A' * 40, MODE_K_ANONYMITY)
        with patch.object(self.qt.QMessageBox, 'information') as info:
            self.plugin._on_async_check_finished(self.parent, self.button, None, None, clean, None)
            self.assertIn('Not found in the checked leak data', info.call_args.args[2])
            self.assertIn('does not prove', info.call_args.args[2])
            self.assertIn('strong or safe', info.call_args.args[2])

    def test_declining_full_hash_never_authorizes_client(self):
        client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH)
        with patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.No) as question:
            self.assertFalse(self.plugin._confirm_disclosure(self.parent, client))
            self.assertIn('https://example.com', question.call_args.args[2])
            self.assertIn('FULL SHA-1', question.call_args.args[2])
        with self.assertRaises(LeakCheckError), patch.object(client, '_http_get') as request:
            client.check_secret('synthetic')
        request.assert_not_called()

    def test_explicit_approval_authorizes_full_hash(self):
        client = PwnedClient('https://example.com/{hash}', MODE_FULL_HASH)
        with patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.Yes):
            self.assertTrue(self.plugin._confirm_disclosure(self.parent, client))
        with patch.object(client, '_http_get', return_value='0'):
            self.assertFalse(client.check_secret('synthetic').is_pwned)

    def test_network_refusal_does_not_prompt_or_start_worker(self):
        self.plugin._require_network_policy = Mock(side_effect=LeakCheckError('offline'))
        self.plugin._confirm_disclosure = Mock()
        self.plugin._start_async_check = Mock()
        field = Mock()
        field.text.return_value = 'synthetic'
        with patch.object(self.qt.QMessageBox, 'warning'):
            self.plugin._on_check_button_clicked(field, self.button)
        self.plugin._confirm_disclosure.assert_not_called()
        self.plugin._start_async_check.assert_not_called()

    def test_cancelled_disclosure_does_not_start_worker(self):
        self.plugin._require_network_policy = Mock()
        self.plugin._build_client = Mock(return_value=PwnedClient('https://example.com/{prefix}'))
        self.plugin._confirm_disclosure = Mock(return_value=False)
        self.plugin._start_async_check = Mock()
        field = Mock()
        field.text.return_value = 'synthetic'
        self.plugin._on_check_button_clicked(field, self.button)
        self.plugin._start_async_check.assert_not_called()

    def test_built_client_rechecks_policy_and_rejects_bad_saved_headers(self):
        self.plugin.name = 'test_plugin'
        self.plugin.config = Mock()
        self.plugin.config.get.side_effect = lambda key, default: default
        self.plugin._require_network_policy = Mock(side_effect=LeakCheckError('proxy enabled'))
        client = self.plugin._build_client()
        with self.assertRaises(LeakCheckError), patch('socket.getaddrinfo') as dns:
            client.check_secret('synthetic')
        dns.assert_not_called()
        for raw in ('not JSON', '[]', '{"Host":"evil.com"}'):
            with self.subTest(raw=raw), self.assertRaises(LeakCheckError):
                self.plugin._headers_from_json(raw)

    def configure(self, **settings):
        self.plugin.name = 'electrum_passphrase_leak_checker'
        self.plugin.config = Mock()
        self.plugin.config.get.side_effect = lambda key, default: settings.get(key.rsplit('.', 1)[-1], default)

    def test_empty_password_never_prompts_or_starts_a_worker(self):
        field = Mock()
        field.text.return_value = ''
        self.plugin._require_network_policy = Mock()
        self.plugin._confirm_disclosure = Mock()
        self.plugin._start_async_check = Mock()
        with patch.object(self.qt.QMessageBox, 'information'):
            self.plugin._on_check_button_clicked(field, self.button)
        self.plugin._require_network_policy.assert_not_called()
        self.plugin._confirm_disclosure.assert_not_called()
        self.plugin._start_async_check.assert_not_called()

    def test_corrupt_saved_settings_raise_handled_errors(self):
        for settings in (
            {'timeout_seconds': 'not-an-integer'}, {'timeout_seconds': None},
            {'timeout_seconds': True}, {'timeout_seconds': 1.5}, {'timeout_seconds': 0},
            {'lookup_mode': 'unknown'}, {'endpoint_template': None},
            {'endpoint_template': 'http://example.com/{prefix}'},
            {'headers_json': None}, {'headers_json': '[]'},
            {'headers_json': '{"X-Test":1}'}, {'headers_json': '{"Host":"other.example"}'},
        ):
            with self.subTest(settings=settings):
                self.configure(**settings)
                with self.assertRaises(LeakCheckError):
                    self.plugin._build_client()

    def test_corrupt_config_cannot_escape_password_button_handler(self):
        self.configure(timeout_seconds='invalid')
        self.plugin._require_network_policy = Mock()
        self.plugin._confirm_disclosure = Mock()
        self.plugin._start_async_check = Mock()
        field = Mock()
        field.text.return_value = 'public test password'
        with patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_check_button_clicked(field, self.button)
        warning.assert_called_once()
        self.plugin._confirm_disclosure.assert_not_called()
        self.plugin._start_async_check.assert_not_called()

    def test_loading_client_preserves_defaults_without_writing_settings(self):
        self.configure()
        client = self.plugin._build_client()
        self.assertEqual(client.endpoint_template, self.plugin.DEFAULT_ENDPOINT)
        self.assertEqual(client.mode, MODE_K_ANONYMITY)
        self.assertEqual(client.timeout_seconds, 7)
        self.assertEqual(client.extra_headers, {'Add-Padding': 'true'})
        self.plugin.config.set_key.assert_not_called()

    def test_settings_entry_point_opens_the_adapter_form(self):
        with patch.object(self.plugin, '_show_settings_dialog') as show:
            self.plugin.settings_dialog(self.parent)
        show.assert_called_once_with(self.parent)

    def test_saved_and_edited_headers_share_strict_validation(self):
        for raw in ('', 'null', '[]', '{"X-Test":true}', '{"X-Test":null}',
                    '{"X-Test":{}}', '{"X-Test":"a","X-Test":"b"}',
                    '{"X-Test":"a","x-test":"b"}', '{"X-Test":"line\\nbreak"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(LeakCheckError):
                    self.plugin._headers_from_json(raw)
                with patch.object(self.qt.QMessageBox, 'warning') as warning:
                    self.assertIsNone(self.plugin._parse_headers(raw, self.parent))
                warning.assert_called_once()
        self.assertEqual(self.plugin._headers_from_json('{"Add-Padding":"true"}'), {'Add-Padding': 'true'})

    def test_prefix_disclosure_names_destination_and_defaults_to_no(self):
        client = PwnedClient('https://example.com/private/{prefix}')
        with patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.No) as question:
            self.assertFalse(self.plugin._confirm_disclosure(self.parent, client))
        message = question.call_args.args[2]
        self.assertIn('https://example.com', message)
        self.assertIn('first five', message)
        self.assertIn('IP address', message)
        self.assertNotIn('/private/', message)
        self.assertEqual(question.call_args.args[-1], self.qt.QMessageBox.StandardButton.No)

    def test_error_takes_precedence_over_an_apparent_match(self):
        result = LeakCheckResult(True, 10, 'A' * 40, MODE_K_ANONYMITY)
        with patch.object(self.qt.QMessageBox, 'warning') as warning, \
                patch.object(self.qt.QMessageBox, 'information') as information:
            self.plugin._on_async_check_finished(self.parent, self.button, None, None, result, 'Unavailable')
        self.assertNotIn('Times seen', warning.call_args.args[2])
        information.assert_not_called()

    def test_valid_match_warns_and_reenables_the_button(self):
        result = LeakCheckResult(True, 26230667, 'A' * 40, MODE_K_ANONYMITY)
        with patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(self.parent, self.button, None, None, result, None)
        self.assertIn('Times seen in leaked data: 26,230,667', warning.call_args.args[2])
        self.assertNotIn(result.sha1_hash, warning.call_args.args[2])
        self.button.setEnabled.assert_called_with(True)

    def test_presence_only_match_never_claims_one_occurrence(self):
        result = LeakCheckResult(True, 1, 'A' * 40, MODE_FULL_HASH, count_reported=False)
        with patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(self.parent, self.button, None, None, result, None)
        message = warning.call_args.args[2]
        self.assertIn('was found', message)
        self.assertIn('did not report how many times', message)
        self.assertNotIn('Times seen', message)
        self.assertNotIn('1', message)

    def test_worker_releases_plaintext_on_success_and_failure(self):
        sentinel = 'public-sentinel-secret-for-retention-tests'
        for failure in (None, LeakCheckError(sentinel), RuntimeError(sentinel)):
            with self.subTest(error=type(failure).__name__):
                client = Mock()
                if failure:
                    client.check_secret.side_effect = failure
                else:
                    client.check_secret.return_value = LeakCheckResult(False, 0, 'A' * 40, MODE_K_ANONYMITY)
                worker = self.qt._LeakCheckWorker(client, sentinel)
                emissions = []
                worker.finished.connect(lambda result, error: emissions.append((result, error)))
                worker.run()
                self.assertIsNone(worker._passphrase)
                self.assertEqual(len(emissions), 1)
                self.assertNotIn(sentinel, str(emissions))
                if failure:
                    self.assertIsNone(emissions[0][0])
                    self.assertIn('Could not check for leaks', emissions[0][1])

    def test_proxy_disclosure_does_not_claim_a_direct_connection(self):
        client = PwnedClient('https://example.invalid/{prefix}', proxy=SocksProxy('127.0.0.1', 9050))
        with patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.No) as question:
            self.assertFalse(self.plugin._confirm_disclosure(self.parent, client))
        message = question.call_args.args[2]
        self.assertIn('SOCKS5', message)
        self.assertIn('proxy resolves', message)
        self.assertIn('not fall back', message)
        self.assertNotIn('connection is direct', message)

    def test_proxy_snapshot_is_bound_to_the_client_and_rechecked_before_io(self):
        self.configure()
        proxy = SocksProxy('127.0.0.1', 9050)
        self.plugin._require_network_policy = Mock(return_value=SocksProxy('127.0.0.1', 9150))
        client = self.plugin._build_client(proxy=proxy)
        self.assertEqual(client.proxy, proxy)
        with patch('socket.getaddrinfo') as dns, patch('socket.socket.connect') as connect, \
                self.assertRaisesRegex(LeakCheckError, 'connection settings changed'):
            client.check_secret('public example')
        dns.assert_not_called()
        connect.assert_not_called()

    def test_proxy_route_cannot_silently_become_direct_after_approval(self):
        self.configure()
        proxy = SocksProxy('127.0.0.1', 9050)
        self.plugin._require_network_policy = Mock(return_value=None)
        client = self.plugin._build_client(proxy=proxy)
        with patch('socket.socket.connect') as connect, self.assertRaises(LeakCheckError):
            client.check_secret('public example')
        connect.assert_not_called()
