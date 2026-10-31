"""Startup extension checks with real offscreen Qt; no wallets or network I/O."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import LeakCheckError, LeakCheckResult, MODE_FULL_HASH, MODE_K_ANONYMITY, PwnedClient
from tests.integration import test_checker_ui as checker_tests
from tests.integration import test_electrum_qt as qt_tests
from tests.readiness.test_settings import Config


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class StartupExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        checker_tests.CheckerUITests.setUpClass()
        cls.qt = checker_tests.CheckerUITests.qt
        cls.widgets = checker_tests.CheckerUITests.widgets
        cls.application = checker_tests.CheckerUITests.application

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.plugin.name = 'electrum_passphrase_leak_checker'
        self.key = self.plugin._cfg_key(self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP)
        self.plugin.config = Config({self.key: True})
        self.window = self.widgets.QWidget()
        self.wallet = Mock(spec_set=('has_seed', 'get_seed_type', 'has_keystore_encryption',
                                     'get_unlocked_password', 'get_keystore'))
        self.wallet.has_seed.return_value = True
        self.wallet.get_seed_type.return_value = 'segwit'
        self.wallet.has_keystore_encryption.return_value = True
        self.wallet.get_unlocked_password.return_value = 'public-unlock-password'
        self.keystore = Mock(spec_set=('get_passphrase', 'get_seed'))
        self.keystore.get_seed.side_effect = AssertionError('Recovery seed must never be read')
        self.keystore.get_passphrase.return_value = ' PUBLIC extension '
        self.wallet.get_keystore.return_value = self.keystore
        self.window.wallet = self.wallet
        self.window.get_password = Mock(return_value='public-unlock-password')
        self.window.show()
        self.client = PwnedClient('https://example.invalid/range/{prefix}')
        self.plugin.config.values.update({
            self.plugin._cfg_key(self.plugin.CFG_ENDPOINT): self.client.endpoint_template,
            self.plugin._cfg_key(self.plugin.CFG_MODE): self.client.mode,
            self.plugin._cfg_key(self.plugin.CFG_HEADERS_JSON): '{}',
            self.plugin._cfg_key(self.plugin.CFG_STARTUP_APPROVAL): self.plugin._startup_approval_for(self.client),
        })
        self.plugin._require_network_policy = Mock(return_value=None)
        self.plugin._confirm_disclosure = Mock(return_value=True)
        self.start = patch.object(self.plugin, '_start_async_check').start()
        self.addCleanup(patch.stopall)
        self.warning = patch.object(self.qt.QMessageBox, 'warning').start()
        self.question = patch.object(self.qt.QMessageBox, 'question',
                                     return_value=self.qt.QMessageBox.StandardButton.No).start()
        self.normalize = Mock(return_value='public extension')
        patch.dict('sys.modules', {'electrum.mnemonic': SimpleNamespace(normalize_text=self.normalize)}).start()

    def tearDown(self):
        self.plugin.close()
        for thread, worker in list(self.plugin._active_checks):
            self.plugin._on_thread_finished(thread, worker)
        self.window.hide()
        self.window.deleteLater()
        self.application.processEvents()

    def schedule(self):
        with patch.object(self.qt.QTimer, 'singleShot') as timer:
            self.plugin.load_wallet(self.wallet, self.window)
        timer.assert_called_once()
        self.assertEqual(timer.call_args.args[0], 0)
        return timer.call_args.args[1]

    def test_disabled_startup_does_not_read_wallet_or_schedule_anything(self):
        self.plugin.config.values.clear()
        with patch.object(self.qt.QTimer, 'singleShot') as timer:
            self.plugin.load_wallet(self.wallet, self.window)
        timer.assert_not_called()
        self.wallet.has_seed.assert_not_called()
        self.window.get_password.assert_not_called()
        self.wallet.get_keystore.assert_not_called()

    def test_enabled_check_is_deferred_and_reads_only_the_extension(self):
        original_settings = dict(self.plugin.config.values)
        self.plugin.load_wallet(self.wallet, self.window)
        self.window.get_password.assert_not_called()
        self.start.assert_not_called()
        self.application.processEvents()
        self.window.get_password.assert_not_called()
        self.wallet.get_unlocked_password.assert_called_once()
        self.keystore.get_passphrase.assert_called_once_with('public-unlock-password')
        self.keystore.get_seed.assert_not_called()
        self.normalize.assert_called_once_with(' PUBLIC extension ')
        self.plugin._confirm_disclosure.assert_not_called()
        self.question.assert_not_called()
        self.start.assert_called_once()
        self.assertEqual(self.start.call_args.kwargs['passphrase'], 'public extension')
        self.assertEqual(self.start.call_args.kwargs['client'].endpoint_template, self.client.endpoint_template)
        self.assertIs(self.start.call_args.kwargs['startup'], self.plugin._startup_checks[self.window])
        self.assertEqual(self.plugin.config.values, original_settings)
        self.assertEqual(self.plugin.config.writes, [])

    def test_repeated_load_notifications_schedule_only_one_attempt(self):
        run = self.schedule()
        with patch.object(self.qt.QTimer, 'singleShot') as timer:
            self.plugin.load_wallet(self.wallet, self.window)
        timer.assert_not_called()
        run()
        self.start.assert_called_once()

    def test_missing_seed_skips_watching_only_imported_and_hardware_wallets(self):
        self.wallet.has_seed.return_value = False
        self.schedule()()
        self.window.get_password.assert_not_called()
        self.wallet.get_keystore.assert_not_called()
        self.plugin._confirm_disclosure.assert_not_called()
        self.start.assert_not_called()

    def test_busy_plugin_skips_the_startup_attempt_without_unlocking(self):
        self.plugin._active_checks = [(Mock(), Mock()) for _ in range(self.plugin.MAX_ACTIVE_CHECKS)]
        self.schedule()()
        self.window.get_password.assert_not_called()
        self.start.assert_not_called()

    def test_settings_checkbox_is_visible_off_by_default_and_saves_the_selection(self):
        self.plugin.config.values.clear()
        dialogs = []

        def dialog(parent, title):
            form = self.widgets.QDialog(parent)
            form.setWindowTitle(title)
            dialogs.append(form)
            return form

        def enter(text, callback):
            button = self.widgets.QPushButton(text)
            button.clicked.connect(callback)
            return button

        def buttons(*controls):
            row = self.widgets.QHBoxLayout()
            for control in controls:
                row.addWidget(control)
            return row

        def execute(form):
            form.show()
            box = form.findChild(self.widgets.QCheckBox, 'passphrase_leak_checker_check_extension_on_startup')
            self.assertIsNotNone(box)
            self.assertTrue(box.isVisible())
            self.assertFalse(box.isChecked())
            box.setChecked(True)
            self.question.assert_called_once()
            self.assertEqual(box.isChecked(), accepted)
            return save

        for accepted, save in ((True, True), (False, True), (True, False)):
            with self.subTest(accepted=accepted, save=save):
                self.plugin.config = Config()
                self.question.reset_mock()
                self.question.return_value = (self.qt.QMessageBox.StandardButton.Yes if accepted
                                              else self.qt.QMessageBox.StandardButton.No)
                with patch.object(self.qt, 'WindowModalDialog', side_effect=dialog), \
                        patch.object(self.qt, 'EnterButton', side_effect=enter), \
                        patch.object(self.qt, 'Buttons', side_effect=buttons), \
                        patch.object(self.qt, 'CancelButton', side_effect=lambda form: self.widgets.QPushButton('Cancel', form)), \
                        patch.object(self.qt, 'OkButton', side_effect=lambda form: self.widgets.QPushButton('OK', form)), \
                        patch.object(self.plugin, '_dialog_exec', side_effect=execute):
                    self.plugin.settings_dialog(self.window)
                self.assertEqual(self.plugin._startup_enabled(), accepted and save)
                self.assertIn('Plugin Settings', dialogs[-1].windowTitle())
                self.question.assert_called_once()  # Save never asks a second time for the same settings.
                self.wallet.get_keystore.assert_not_called()
                if not save:
                    self.assertEqual(self.plugin.config.writes, [])
        self.window.get_password.assert_not_called()
        for form in dialogs:
            form.hide()
            form.deleteLater()

    def test_locked_wallet_never_prompts_reads_the_extension_or_starts_check(self):
        self.wallet.get_unlocked_password.return_value = None
        self.schedule()()
        self.wallet.get_keystore.assert_not_called()
        self.plugin._confirm_disclosure.assert_not_called()
        self.start.assert_not_called()
        self.warning.assert_not_called()
        self.question.assert_not_called()
        self.window.get_password.assert_not_called()

    def test_unencrypted_wallet_uses_the_host_getter_without_a_password(self):
        self.wallet.has_keystore_encryption.return_value = False
        self.window.get_password.return_value = None
        self.schedule()()
        self.keystore.get_passphrase.assert_called_once_with(None)
        self.wallet.get_unlocked_password.assert_not_called()
        self.start.assert_called_once()

    def test_empty_extension_never_prompts_for_disclosure_or_starts_check(self):
        self.keystore.get_passphrase.return_value = ''
        self.schedule()()
        self.plugin._confirm_disclosure.assert_not_called()
        self.start.assert_not_called()

    def test_enabled_flag_without_settings_approval_never_schedules_a_request(self):
        self.plugin.config.values.pop(self.plugin._cfg_key(self.plugin.CFG_STARTUP_APPROVAL))
        with patch.object(self.qt.QTimer, 'singleShot') as timer:
            self.plugin.load_wallet(self.wallet, self.window)
        timer.assert_not_called()
        self.start.assert_not_called()
        self.question.assert_not_called()
        self.wallet.get_keystore.assert_not_called()

    def test_malformed_or_unknown_approval_is_not_permission_to_autocheck(self):
        key = self.plugin._cfg_key(self.plugin.CFG_STARTUP_APPROVAL)
        original = self.plugin._startup_approval_for(self.client)
        for approval in (None, [], {}, dict(original, version=True), dict(original, version=2)):
            with self.subTest(approval=approval):
                self.plugin.config.values[key] = approval
                with patch.object(self.qt.QTimer, 'singleShot') as timer:
                    self.plugin.load_wallet(self.wallet, self.window)
                timer.assert_not_called()
                self.wallet.get_keystore.assert_not_called()

    def test_offline_or_unverifiable_route_refuses_before_unlock(self):
        self.plugin._require_network_policy.side_effect = LeakCheckError('offline')
        self.schedule()()
        self.window.get_password.assert_not_called()
        self.wallet.get_keystore.assert_not_called()
        self.start.assert_not_called()

    def test_route_change_before_start_prevents_worker_start(self):
        self.plugin._require_network_policy.side_effect = [None, LeakCheckError('route changed')]
        self.schedule()()
        self.plugin._confirm_disclosure.assert_not_called()
        self.start.assert_not_called()

    def test_closed_hidden_replaced_wallet_or_disabled_plugin_suppresses_pending_callback(self):
        for change in ('close', 'hide', 'replace', 'disable', 'setting'):
            with self.subTest(change=change):
                self.plugin._startup_checks.clear()
                run = self.schedule()
                if change == 'close':
                    self.plugin.on_close_window(self.window)
                elif change == 'hide':
                    self.window.hide()
                elif change == 'replace':
                    self.window.wallet = object()
                elif change == 'disable':
                    self.plugin._closing = True
                else:
                    self.plugin.config.values[self.key] = False
                run()
                self.start.assert_not_called()
                self.window.get_password.assert_not_called()
                self.window.show()
                self.window.wallet = self.wallet
                self.plugin._closing = False
                self.plugin.config.values[self.key] = True

    def test_window_closed_when_retrieving_cached_password_does_not_read_extension(self):
        def cached_password():
            self.plugin.on_close_window(self.window)
            return 'public-unlock-password'
        self.wallet.get_unlocked_password.side_effect = cached_password
        self.schedule()()
        self.wallet.get_keystore.assert_not_called()
        self.start.assert_not_called()

    def test_seed_format_changed_before_start_prevents_worker_start(self):
        def extension(*args):
            self.wallet.get_seed_type.return_value = 'bip39'
            return 'public extension'
        self.keystore.get_passphrase.side_effect = extension
        self.schedule()()
        self.start.assert_not_called()

    def test_disabling_setting_before_start_prevents_worker_start(self):
        def extension(*args):
            self.plugin._save_settings({self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP: False})
            return 'public extension'
        self.keystore.get_passphrase.side_effect = extension
        self.schedule()()
        self.start.assert_not_called()

    def test_unsupported_seed_format_and_host_errors_never_expose_diagnostics(self):
        for failure in ('format', 'read'):
            with self.subTest(failure=failure):
                self.plugin._startup_checks.clear()
                self.wallet.get_seed_type.return_value = 'unknown' if failure == 'format' else 'segwit'
                self.keystore.get_passphrase.side_effect = RuntimeError('public-private-diagnostic') if failure == 'read' else None
                self.schedule()()
                self.start.assert_not_called()
                self.warning.assert_not_called()
                self.question.assert_not_called()

    def test_seed_like_extension_is_still_refused_locally(self):
        self.keystore.get_passphrase.return_value = ' '.join(['abandon'] * 11 + ['about'])
        with patch.dict('sys.modules', {
            'electrum.mnemonic': SimpleNamespace(is_seed=lambda value: True),
            'electrum.keystore': SimpleNamespace(bip39_is_checksum_valid=lambda value: (True, True)),
        }):
            self.schedule()()
        self.start.assert_not_called()
        self.plugin._confirm_disclosure.assert_not_called()

    def test_buttonless_check_delivers_results_and_is_cancelled_when_window_closes(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        thread, worker = Mock(), Mock()
        # Exercise worker ownership without starting a thread.
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        result = LeakCheckResult(True, 12, None, MODE_K_ANONYMITY)
        with patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(self.window, None, thread, worker, result, None)
            warning.assert_called_once()
            self.assertIn('seed extension was found', warning.call_args.args[2])
            self.assertNotIn('public extension', warning.call_args.args[2])
            self.plugin.on_close_window(self.window)
            worker.cancel.assert_called_once()
            self.plugin._on_async_check_finished(self.window, None, thread, worker, result, None)
            warning.assert_called_once()

    def test_hidden_window_or_replaced_wallet_cannot_receive_startup_result(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        thread, worker = Mock(), Mock()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        result = LeakCheckResult(True, 12, None, MODE_K_ANONYMITY)
        with patch.object(self.qt.QMessageBox, 'information') as info:
            self.window.hide()
            self.plugin._on_async_check_finished(self.window, None, thread, worker, result, None)
            self.window.show()
            self.window.wallet = object()
            self.plugin._on_async_check_finished(self.window, None, thread, worker, result, None)
        info.assert_not_called()
        self.warning.assert_not_called()

    def test_startup_no_match_errors_and_missing_results_are_silent(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        thread, worker = Mock(), Mock()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        with patch.object(self.qt.QMessageBox, 'information') as info:
            for result, error in ((LeakCheckResult(False, 0, None, MODE_K_ANONYMITY), None),
                                  (None, 'unavailable'), (None, None),
                                  (LeakCheckResult(True, 1, None, MODE_K_ANONYMITY), 'error')):
                self.plugin._on_async_check_finished(self.window, None, thread, worker, result, error)
        info.assert_not_called()
        self.warning.assert_not_called()
        self.question.assert_not_called()

    def test_startup_worker_creation_failure_is_also_silent(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        with patch.object(self.qt, 'QThread', side_effect=RuntimeError('public startup failure')):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        self.assertEqual(self.plugin._active_checks, [])
        self.warning.assert_not_called()
        self.question.assert_not_called()

    def test_approval_cannot_silently_follow_a_changed_service_mode_or_headers(self):
        changes = ((self.plugin.CFG_ENDPOINT, 'https://another.invalid/{prefix}'),
                   (self.plugin.CFG_MODE, MODE_FULL_HASH),
                   (self.plugin.CFG_HEADERS_JSON, '{"Add-Padding":"true"}'))
        for key, value in changes:
            with self.subTest(key=key):
                full_key = self.plugin._cfg_key(key)
                previous = self.plugin.config.values[full_key]
                self.plugin.config.values[full_key] = value
                with patch.object(self.qt.QTimer, 'singleShot') as timer:
                    self.plugin.load_wallet(self.wallet, self.window)
                timer.assert_not_called()
                self.wallet.get_keystore.assert_not_called()
                self.plugin.config.values[full_key] = previous

    def test_full_hash_startup_requires_its_matching_saved_approval(self):
        client = PwnedClient('https://example.invalid/{hash}', MODE_FULL_HASH)
        self.plugin.config.values.update({
            self.plugin._cfg_key(self.plugin.CFG_ENDPOINT): client.endpoint_template,
            self.plugin._cfg_key(self.plugin.CFG_MODE): client.mode,
            self.plugin._cfg_key(self.plugin.CFG_STARTUP_APPROVAL): self.plugin._startup_approval_for(client),
        })
        self.schedule()()
        actual = self.start.call_args.kwargs['client']
        self.assertEqual(actual._consented_destination, client.destination)
        self.question.assert_not_called()

    def test_saving_off_cancels_active_startup_checks(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        thread, worker = Mock(), Mock()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        self.plugin._save_settings({self.plugin.CFG_CHECK_EXTENSION_ON_STARTUP: False})
        worker.cancel.assert_called_once()
        self.assertFalse(self.plugin._check_contexts[thread]['valid'])

    def test_service_change_cancels_active_startup_checks(self):
        self.schedule()
        state = self.plugin._startup_checks[self.window]
        thread, worker = Mock(), Mock()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.qt.Plugin._start_async_check(self.plugin, self.window, None, self.client,
                                             'public extension', startup=state)
        self.plugin._save_settings({self.plugin.CFG_ENDPOINT: 'https://new.invalid/{prefix}'})
        worker.cancel.assert_called_once()
        self.assertFalse(self.plugin._check_contexts[thread]['valid'])
