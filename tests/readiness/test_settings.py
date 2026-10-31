"""Settings persistence and repair with a host-like config, without Electrum."""

import copy
from threading import RLock
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import LeakCheckError
from tests.integration import test_electrum_qt as qt_tests


class Config:
    def __init__(self, values=None):
        self.values = dict(values or {})
        self.persisted = copy.deepcopy(self.values)
        self.lock = RLock()
        self.locked = set()
        self.writes = []
        self.saves = 0
        self.fail_save = False
        self.fail_key = None

    def get(self, key, default=None):
        return self.values.get(key, default)

    def is_modifiable(self, key):
        return key not in self.locked

    def set_key(self, key, value, *, save=True):
        self.writes.append((key, value, save))
        if key == self.fail_key:
            self.fail_key = None
            raise OSError('private config diagnostic')
        if not self.is_modifiable(key):
            return
        if value is None:
            self.values.pop(key, None)
        else:
            self.values[key] = value
        if save:
            self.save_user_config()

    def save_user_config(self):
        self.saves += 1
        if self.fail_save:
            raise OSError('private save diagnostic')
        self.persisted = copy.deepcopy(self.values)


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class SettingsRequirements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qt_tests.PluginUITests.setUpClass()
        cls.qt = qt_tests.PluginUITests.qt

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.plugin.name = 'electrum_passphrase_leak_checker'
        self.plugin.config = Config()
        self.settings = {
            self.plugin.CFG_ENDPOINT: 'https://example.invalid/range/{prefix}',
            self.plugin.CFG_MODE: 'k_anonymity',
            self.plugin.CFG_TIMEOUT: 9,
            self.plugin.CFG_HEADERS_JSON: '{"Add-Padding": "true"}',
        }

    def tearDown(self):
        self.plugin.close()

    def widgets(self):
        widgets = {name: Mock() for name in (
            'WindowModalDialog', 'QVBoxLayout', 'QLabel', 'QFormLayout', 'QLineEdit',
            'QComboBox', 'QSpinBox', 'QCheckBox', 'QPlainTextEdit', 'Buttons', 'CancelButton', 'OkButton',
        )}
        widgets['QLineEdit'].return_value.text.return_value = self.settings[self.plugin.CFG_ENDPOINT]
        widgets['QComboBox'].return_value.findData.return_value = 0
        widgets['QComboBox'].return_value.currentData.return_value = 'k_anonymity'
        widgets['QSpinBox'].return_value.value.return_value = 9
        widgets['QCheckBox'].return_value.isChecked.return_value = False
        widgets['QPlainTextEdit'].return_value.toPlainText.return_value = '{"Add-Padding":"true"}'
        return widgets

    def test_all_settings_are_staged_before_a_single_save(self):
        self.plugin._save_settings(self.settings)
        self.assertEqual(self.plugin.config.saves, 1)
        self.assertTrue(all(not save for _, _, save in self.plugin.config.writes))
        self.assertEqual(self.plugin.config.persisted, {
            self.plugin._cfg_key(key): value for key, value in self.settings.items()
        })
        self.assertEqual(self.plugin._build_client().timeout_seconds, 9)

    def test_startup_option_defaults_to_off_and_persists_only_when_saved(self):
        self.assertFalse(self.plugin._startup_enabled())
        widgets = self.widgets()
        widgets['QCheckBox'].return_value.isChecked.return_value = True
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', return_value=False):
            self.plugin.settings_dialog(Mock())
        widgets['QCheckBox'].return_value.setChecked.assert_called_with(False)
        self.assertFalse(self.plugin._startup_enabled())
        self.assertEqual(self.plugin.config.writes, [])
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', return_value=True), \
                patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.Yes) as confirm:
            self.plugin.settings_dialog(Mock())
        confirm.assert_called_once()
        self.assertTrue(self.plugin._startup_enabled())
        self.assertIs(self.plugin.config.persisted[self.plugin._cfg_key(
            self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP)], True)
        self.assertEqual(self.plugin.config.saves, 1)

    def test_startup_confirmation_describes_ongoing_disclosure_and_defaults_to_no(self):
        from passphrase_leak_checker.client import MODE_FULL_HASH, PwnedClient
        for client in (PwnedClient('https://example.invalid/{prefix}'),
                       PwnedClient('https://example.invalid/{hash}', MODE_FULL_HASH)):
            with patch.object(self.qt.QMessageBox, 'question', return_value=self.qt.QMessageBox.StandardButton.No) as confirm:
                self.assertFalse(self.plugin._confirm_startup_disclosure(Mock(), client))
            message = confirm.call_args.args[2]
            self.assertIn(client.destination, message)
            self.assertIn('future startup checks', message)
            self.assertIn('Locked or unavailable', message)
            self.assertIn('failed checks stay silent', message)
            self.assertEqual(confirm.call_args.args[-1], self.qt.QMessageBox.StandardButton.No)
            self.assertIn('FULL SHA-1' if client.mode == MODE_FULL_HASH else 'first five', message)

    def test_changing_service_with_startup_enabled_requires_new_confirmation_in_settings(self):
        from passphrase_leak_checker.client import PwnedClient
        for accept in (False, True):
            with self.subTest(accept=accept):
                client = PwnedClient(self.settings[self.plugin.CFG_ENDPOINT],
                                     extra_headers={'Add-Padding': 'true'})
                saved = dict(self.settings, **{
                    self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP: True,
                    self.plugin.CFG_STARTUP_APPROVAL: self.plugin._startup_approval_for(client),
                })
                self.plugin.config = Config({self.plugin._cfg_key(key): value for key, value in saved.items()})
                widgets = self.widgets()
                widgets['QLineEdit'].return_value.text.return_value = 'https://new.invalid/{prefix}'
                widgets['QCheckBox'].return_value.isChecked.return_value = True
                answer = self.qt.QMessageBox.StandardButton.Yes if accept else self.qt.QMessageBox.StandardButton.No
                with patch.multiple(self.qt, **widgets), \
                        patch.object(self.plugin, '_dialog_exec', return_value=True), \
                        patch.object(self.qt.QMessageBox, 'question', return_value=answer) as confirm:
                    self.plugin.settings_dialog(Mock())
                confirm.assert_called_once()
                self.assertIn('https://new.invalid', confirm.call_args.args[2])
                self.assertEqual(self.plugin._startup_enabled(), accept)

    def test_non_boolean_startup_settings_cannot_enable_or_be_saved(self):
        key = self.plugin._cfg_key(self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP)
        for value in ('true', 'false', 1, 0, None, [], {}):
            with self.subTest(value=value):
                self.plugin.config.values[key] = value
                self.assertFalse(self.plugin._startup_enabled())
                with self.assertRaises(LeakCheckError):
                    self.plugin._save_settings({self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP: value})
        self.assertEqual(self.plugin.config.writes, [])

    def test_startup_option_is_rolled_back_with_other_settings_on_save_failure(self):
        self.plugin.config.fail_save = True
        settings = dict(self.settings, **{self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP: True})
        with self.assertRaises(LeakCheckError):
            self.plugin._save_settings(settings)
        self.assertFalse(self.plugin._startup_enabled())
        self.assertEqual(self.plugin.config.values, {})

    def test_failed_save_restores_previous_memory_and_does_not_retry_disk(self):
        key = self.plugin._cfg_key(self.plugin.CFG_ENDPOINT)
        self.plugin.config = Config({key: 'https://previous.invalid/{prefix}', 'unrelated': 1})
        before = copy.deepcopy(self.plugin.config.values)
        self.plugin.config.fail_save = True
        with self.assertRaises(LeakCheckError) as raised:
            self.plugin._save_settings(self.settings)
        self.assertNotIn('private', str(raised.exception))
        self.assertEqual(self.plugin.config.values, before)
        self.assertEqual(self.plugin.config.persisted, before)
        self.assertEqual(self.plugin.config.saves, 1)

    def test_staging_error_restores_all_prior_values_without_saving(self):
        self.plugin.config.fail_key = self.plugin._cfg_key(self.plugin.CFG_TIMEOUT)
        with self.assertRaises(LeakCheckError):
            self.plugin._save_settings(self.settings)
        self.assertEqual(self.plugin.config.values, {})
        self.assertEqual(self.plugin.config.saves, 0)

    def test_locked_setting_refuses_every_write(self):
        self.plugin.config.locked.add(self.plugin._cfg_key(self.plugin.CFG_MODE))
        with self.assertRaises(LeakCheckError):
            self.plugin._save_settings(self.settings)
        self.assertEqual(self.plugin.config.writes, [])
        self.assertEqual(self.plugin.config.saves, 0)

    def test_silently_ignored_update_cannot_be_reported_as_a_save(self):
        with patch.object(self.plugin.config, 'set_key'), self.assertRaises(LeakCheckError):
            self.plugin._save_settings(self.settings)
        self.assertEqual(self.plugin.config.values, {})
        self.assertEqual(self.plugin.config.saves, 0)

    def test_failed_rollback_blocks_checks_until_settings_are_repaired(self):
        config = self.plugin.config
        original_set = config.set_key
        config.fail_save = True
        def fail_rollback(key, value, **kwargs):
            if value is None:
                raise OSError('private rollback diagnostic')
            return original_set(key, value, **kwargs)
        with patch.object(config, 'set_key', side_effect=fail_rollback), self.assertRaises(LeakCheckError):
            self.plugin._save_settings(self.settings)
        with self.assertRaisesRegex(LeakCheckError, 'recovery failed'):
            self.plugin._build_client()
        config.fail_save = False
        self.plugin._save_settings(self.settings)
        self.assertEqual(self.plugin._build_client().timeout_seconds, 9)

    def test_invalid_form_can_be_corrected_without_recreating_or_losing_edits(self):
        widgets = self.widgets()
        widgets['QLineEdit'].return_value.text.side_effect = ['', self.settings[self.plugin.CFG_ENDPOINT]]
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', side_effect=[True, True]) as execute, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin.settings_dialog(Mock())
        self.assertEqual(execute.call_count, 2)
        widgets['WindowModalDialog'].assert_called_once()
        warning.assert_called_once()
        self.assertEqual(self.plugin.config.saves, 1)

    def test_failed_save_preserves_form_for_retry(self):
        widgets = self.widgets()
        self.plugin.config.fail_save = True
        def execute(dialog):
            if self.plugin.config.saves:
                self.plugin.config.fail_save = False
            return True
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', side_effect=execute) as run, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin.settings_dialog(Mock())
        self.assertEqual(run.call_count, 2)
        self.assertEqual(self.plugin.config.saves, 2)
        warning.assert_called_once()
        self.assertNotIn('private', str(warning.call_args))

    def test_cancel_after_invalid_headers_never_changes_config(self):
        widgets = self.widgets()
        widgets['QPlainTextEdit'].return_value.toPlainText.return_value = '{"Host":"unsafe.invalid"}'
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', side_effect=[True, False]) as execute, \
                patch.object(self.qt.QMessageBox, 'warning'):
            self.plugin.settings_dialog(Mock())
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(self.plugin.config.writes, [])
        self.assertEqual(self.plugin.config.saves, 0)

    def test_settings_provides_a_direct_checker_entry_point(self):
        widgets = self.widgets()
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.qt, 'EnterButton') as button, \
                patch.object(self.plugin, '_show_check_dialog') as show, \
                patch.object(self.plugin, '_dialog_exec', return_value=False):
            self.plugin.settings_dialog(Mock())
        self.assertIn('Check', button.call_args.args[0])
        button.call_args.args[1]()
        show.assert_called_once_with(widgets['WindowModalDialog'].return_value)

    def test_existing_credentials_are_hidden_block_checks_and_change_only_after_save(self):
        key = self.plugin._cfg_key(self.plugin.CFG_HEADERS_JSON)
        old = '{"Authorization":"Bearer public-test-sentinel"}'
        self.plugin.config.values[key] = old
        with self.assertRaises(LeakCheckError):
            self.plugin._build_client()
        widgets = self.widgets()
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', return_value=False), \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin.settings_dialog(Mock())
        self.assertNotIn('public-test-sentinel', str(widgets['QPlainTextEdit'].call_args))
        self.assertNotIn('public-test-sentinel', str(warning.call_args))
        self.assertEqual(self.plugin.config.values[key], old)
        self.assertEqual(self.plugin.config.saves, 0)
        with patch.multiple(self.qt, **self.widgets()), \
                patch.object(self.plugin, '_dialog_exec', return_value=True), \
                patch.object(self.qt.QMessageBox, 'warning'):
            self.plugin.settings_dialog(Mock())
        self.assertEqual(self.plugin.config.saves, 1)
        self.assertEqual(self.plugin._build_client().extra_headers, {'Add-Padding': 'true'})

    def test_custom_and_authentication_headers_cannot_be_persisted_through_ui(self):
        for name in ('Authorization', 'Cookie', 'X-Api-Key', 'User-Agent', 'Accept'):
            with self.subTest(name=name), self.assertRaises(LeakCheckError):
                self.plugin._headers_from_json('{"' + name + '":"public-test-sentinel"}')
