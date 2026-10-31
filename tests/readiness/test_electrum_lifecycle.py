"""Required lifecycle behavior, exercised without threads, sockets, or waiting.

Keep these release requirements visible rather than skipping or xfail-ing failures.
"""

import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import LeakCheckResult, MODE_K_ANONYMITY, PwnedClient
from tests.integration import test_electrum_qt as qt_tests


class Signal:
    def __init__(self):
        self.callbacks = []

    def connect(self, callback, *args, **kwargs):
        self.callbacks.append(callback)

    def disconnect(self, callback):
        self.callbacks.remove(callback)

    def emit(self, *args):
        for callback in list(self.callbacks):
            callback(*args)


class Field:
    def __init__(self, parent):
        self.value = 'public original password'
        self.parent = parent
        self.textChanged = Signal()
        self.destroyed = Signal()

    def text(self):
        return self.value

    def window(self):
        return self.parent

    def setText(self, text):
        self.value = text
        self.textChanged.emit(text)


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class ElectrumLifecycleRequirements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qt_tests.PluginUITests.setUpClass()
        cls.qt = qt_tests.PluginUITests.qt

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.parent = Mock()
        self.button = Mock()
        self.button.window.return_value = self.parent
        self.result = LeakCheckResult(False, 0, 'A' * 40, MODE_K_ANONYMITY)

    def tearDown(self):
        # The threads in this module are mocks; release their test-only keepalive.
        self.plugin.close()
        for thread, worker in list(self.plugin._active_checks):
            self.plugin._on_thread_finished(thread, worker)
        self.qt._CLOSING_PLUGINS.discard(self.plugin)

    def pending(self):
        thread = Mock()
        thread.wait.return_value = False
        thread.isRunning.return_value = True
        worker = Mock()
        self.plugin._active_checks.append((thread, worker))
        return thread, worker

    def test_shutdown_keeps_ownership_of_a_worker_that_has_not_stopped(self):
        thread, worker = self.pending()
        self.plugin.close()
        self.assertIn((thread, worker), self.plugin._active_checks,
                      'Shutdown dropped ownership of a still-running worker.')
        thread.deleteLater.assert_not_called()

    def test_result_delivery_keeps_thread_owned_until_finished(self):
        thread, worker = self.pending()
        with patch.object(self.qt.QMessageBox, 'information'):
            self.plugin._on_async_check_finished(self.parent, self.button, thread, worker, self.result, None)
        self.assertIn((thread, worker), self.plugin._active_checks,
                      'A result signal does not establish that the QThread has terminated.')

    def test_shutdown_ignores_late_results(self):
        thread, worker = self.pending()
        self.plugin.close()
        with patch.object(self.qt.QMessageBox, 'information') as info, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(self.parent, self.button, thread, worker, self.result, None)
        info.assert_not_called()
        warning.assert_not_called()

    def test_destroyed_dialog_cannot_receive_an_unparented_result(self):
        thread, worker = self.pending()
        self.button.window.side_effect = RuntimeError('deleted Qt object')
        self.parent.window.side_effect = RuntimeError('deleted Qt object')
        with patch.object(self.qt.QMessageBox, 'information') as info, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(self.parent, self.button, thread, worker, self.result, None)
        info.assert_not_called()
        warning.assert_not_called()

    def test_editing_the_password_invalidates_the_pending_result(self):
        field = Field(self.parent)
        thread = Mock()
        thread.started = Signal()
        thread.finished = Signal()
        worker = Mock()
        worker.finished = Signal()
        self.plugin._require_network_policy = Mock()
        self.plugin._build_client = Mock(return_value=PwnedClient('https://example.com/{prefix}'))
        self.plugin._confirm_disclosure = Mock(return_value=True)
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker), \
                patch.object(self.qt.QMessageBox, 'information') as info, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_check_button_clicked(field, self.button)
            thread.start.assert_called_once()
            field.setText('public replacement password')
            worker.finished.emit(self.result, None)
        info.assert_not_called()
        warning.assert_not_called()

    def test_corrupt_saved_timeout_can_be_opened_for_repair(self):
        self.plugin.name = 'electrum_passphrase_leak_checker'
        self.plugin.config = Mock()
        self.plugin.config.get.side_effect = lambda key, default: 'invalid' if key.endswith('.timeout_seconds') else default
        widgets = {name: Mock() for name in (
            'WindowModalDialog', 'QVBoxLayout', 'QLabel', 'QFormLayout', 'QLineEdit',
            'QComboBox', 'QSpinBox', 'QCheckBox', 'QPlainTextEdit', 'Buttons', 'CancelButton', 'OkButton',
        )}
        widgets['QComboBox'].return_value.findData.return_value = 0
        with patch.multiple(self.qt, **widgets), \
                patch.object(self.plugin, '_dialog_exec', return_value=False) as execute, \
                patch.object(self.qt.QMessageBox, 'warning'):
            try:
                self.plugin.settings_dialog(self.parent)
            except Exception as exc:
                self.fail(f'Corrupt saved timeout prevented settings repair: {type(exc).__name__}')
        execute.assert_called_once()
        self.plugin.config.set_key.assert_not_called()

    def test_finished_thread_is_released_even_without_a_result_signal(self):
        thread = Mock()
        thread.started = Signal()
        thread.finished = Signal()
        worker = Mock()
        worker.finished = Signal()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.plugin._start_async_check(self.parent, self.button,
                                          PwnedClient('https://example.com/{prefix}'), 'public test')
        self.assertIn((thread, worker), self.plugin._active_checks)
        thread.isRunning.return_value = False
        thread.finished.emit()
        self.assertNotIn((thread, worker), self.plugin._active_checks,
                         'Thread termination must clean up ownership on every completion path.')

    def test_unchanged_live_dialog_receives_its_result(self):
        thread = Mock()
        thread.started = Signal()
        thread.finished = Signal()
        worker = Mock()
        worker.finished = Signal()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker), \
                patch.object(self.qt.QMessageBox, 'information') as info:
            self.plugin._start_async_check(self.parent, self.button,
                                          PwnedClient('https://example.com/{prefix}'), 'public test')
            worker.finished.emit(self.result, None)
        info.assert_called_once()
        self.assertIs(info.call_args.args[0], self.parent)
        self.assertIn('Not found in the checked leak data', info.call_args.args[2])

    def test_close_cancels_the_worker_and_releases_keepalive_after_finish(self):
        thread, worker = self.pending()
        self.plugin.close()
        worker.cancel.assert_called_once()
        self.assertIn(self.plugin, self.qt._CLOSING_PLUGINS)
        self.plugin._on_thread_finished(thread, worker)
        self.assertNotIn(self.plugin, self.qt._CLOSING_PLUGINS)

    def test_cancellation_error_does_not_drop_a_running_thread(self):
        thread, worker = self.pending()
        worker.cancel.side_effect = RuntimeError('public cancellation failure')
        self.plugin.close()
        self.assertIn((thread, worker), self.plugin._active_checks)
        thread.quit.assert_called_once()

    def test_closed_plugin_never_captures_a_new_password(self):
        self.plugin.close()
        field = Mock()
        with patch.object(self.qt, 'QThread') as thread:
            self.plugin._on_check_button_clicked(field, self.button)
        field.text.assert_not_called()
        thread.assert_not_called()

    def test_password_changed_during_disclosure_does_not_start_a_request(self):
        field = Field(self.parent)
        self.plugin._require_network_policy = Mock()
        self.plugin._build_client = Mock(return_value=PwnedClient('https://example.com/{prefix}'))
        def approve(parent, client):
            field.setText('public replacement password')
            return True
        self.plugin._confirm_disclosure = approve
        with patch.object(self.qt, 'QThread') as thread:
            self.plugin._on_check_button_clicked(field, self.button)
        thread.assert_not_called()

    def test_thread_completion_disconnects_input_revision_listeners(self):
        field = Field(self.parent)
        thread, worker = Mock(), Mock()
        thread.started, thread.finished, worker.finished = Signal(), Signal(), Signal()
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker):
            self.plugin._start_async_check(self.parent, self.button,
                                          PwnedClient('https://example.com/{prefix}'), 'public original', source=field)
        field.setText('public changed')
        worker.cancel.assert_called_once()
        thread.finished.emit()
        self.assertEqual(field.textChanged.callbacks, [])
        self.assertEqual(field.destroyed.callbacks, [])
        self.assertEqual(self.plugin._check_contexts, {})
        self.assertEqual(self.plugin._active_checks, [])

    def test_concurrent_workers_are_bounded(self):
        threads, workers = [], []
        for _ in range(self.plugin.MAX_ACTIVE_CHECKS):
            thread, worker = Mock(), Mock()
            thread.started, thread.finished, worker.finished = Signal(), Signal(), Signal()
            threads.append(thread)
            workers.append(worker)
        buttons = [Mock() for _ in range(self.plugin.MAX_ACTIVE_CHECKS + 1)]
        with patch.object(self.qt, 'QThread', side_effect=threads) as factory, \
                patch.object(self.qt, '_LeakCheckWorker', side_effect=workers):
            for button in buttons:
                self.plugin._start_async_check(self.parent, button,
                                              PwnedClient('https://example.com/{prefix}'), 'public test')
        self.assertEqual(factory.call_count, self.plugin.MAX_ACTIVE_CHECKS)
        self.assertEqual(len(self.plugin._active_checks), self.plugin.MAX_ACTIVE_CHECKS)

    def test_application_shutdown_joins_threads_after_cancellation(self):
        thread, worker = self.pending()
        thread.wait.return_value = True
        self.plugin._wait_for_shutdown()
        worker.cancel.assert_called_once()
        thread.wait.assert_called_once_with()
        self.assertEqual(self.plugin._active_checks, [])

    def test_failed_join_does_not_release_thread_ownership(self):
        thread, worker = self.pending()
        self.plugin._wait_for_shutdown()
        self.assertIn((thread, worker), self.plugin._active_checks)

    def test_thread_creation_failure_restores_the_button_without_exposing_errors(self):
        field = Field(self.parent)
        self.plugin._require_network_policy = Mock()
        self.plugin._build_client = Mock(return_value=Mock())
        self.plugin._confirm_disclosure = Mock(return_value=True)
        with patch.object(self.qt, 'QThread', side_effect=RuntimeError(field.value)), \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_check_button_clicked(field, self.button)
        self.button.setEnabled.assert_called_with(True)
        warning.assert_called_once()
        self.assertNotIn(field.value, str(warning.call_args))
        self.assertEqual(self.plugin._active_checks, [])

    def test_start_failure_releases_real_worker_secret_and_input_listeners(self):
        field = Field(self.parent)
        thread = self.qt.QThread()
        client = Mock()
        worker = self.qt._LeakCheckWorker(client, field.value)
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(thread, 'start', side_effect=RuntimeError(field.value)), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker), \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._start_async_check(self.parent, self.button, client, field.value, source=field)
        self.assertIsNone(worker._passphrase)
        client.cancel.assert_called_once()
        self.assertEqual(self.plugin._active_checks, [])
        self.assertEqual(self.plugin._check_contexts, {})
        self.assertEqual(field.textChanged.callbacks, [])
        self.assertEqual(field.destroyed.callbacks, [])
        self.button.setEnabled.assert_called_with(True)
        warning.assert_called_once()
        self.assertNotIn(field.value, str(warning.call_args))

    def test_signal_setup_failure_cleans_up_before_starting_a_thread(self):
        field = Field(self.parent)
        field.textChanged = Mock()
        field.textChanged.connect.side_effect = RuntimeError(field.value)
        thread, worker, client = Mock(), Mock(), Mock()
        thread.isRunning.return_value = False
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker), \
                patch.object(self.qt.QMessageBox, 'warning'):
            self.plugin._start_async_check(self.parent, self.button, client, field.value, source=field)
        thread.start.assert_not_called()
        self.assertEqual(self.plugin._check_contexts, {})
        self.assertEqual(self.plugin._active_checks, [])
        self.assertIsNone(worker._passphrase)
        client.cancel.assert_called_once()

    def test_start_exception_cannot_drop_a_thread_that_did_start(self):
        thread, worker, client = Mock(), Mock(), Mock()
        thread.started, thread.finished, worker.finished = Signal(), Signal(), Signal()
        thread.start.side_effect = RuntimeError('public start error')
        thread.isRunning.return_value = True
        with patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker), \
                patch.object(self.qt.QMessageBox, 'warning'):
            self.plugin._start_async_check(self.parent, self.button, client, 'public test')
        self.assertIn((thread, worker), self.plugin._active_checks)
        self.assertFalse(self.plugin._check_contexts[thread]['valid'])
        client.cancel.assert_called_once()
        with patch.object(self.qt.QMessageBox, 'information') as info:
            worker.finished.emit(self.result, None)
        info.assert_not_called()
        thread.finished.emit()
        self.assertEqual(self.plugin._active_checks, [])
