"""Check Qt worker threads with synthetic clients."""

from threading import Event
import time
import unittest
from unittest.mock import Mock, patch

from passphrase_leak_checker.client import LeakCheckResult, MODE_K_ANONYMITY
from tests.integration import test_electrum_qt as qt_tests


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class QtThreadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qt_tests.PluginUITests.setUpClass()
        cls.qt = qt_tests.PluginUITests.qt
        cls.application = cls.qt.QCoreApplication.instance() or cls.qt.QCoreApplication([])

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.parent, self.button = Mock(), Mock()
        self.button.window.return_value = self.parent
        self.result = LeakCheckResult(False, 0, 'A' * 40, MODE_K_ANONYMITY)

    def pump_until(self, predicate):
        deadline = time.monotonic() + 1
        while not predicate() and time.monotonic() < deadline:
            self.application.processEvents()
            self.qt.QThread.yieldCurrentThread()
        self.assertTrue(predicate(), 'Qt worker did not complete within the short local test deadline.')

    def tearDown(self):
        self.plugin._wait_for_shutdown()
        self.application.processEvents()

    def test_real_worker_result_and_thread_cleanup_reach_the_main_thread(self):
        client = Mock()
        client.check_secret.return_value = self.result
        with patch.object(self.qt.QMessageBox, 'information') as info:
            self.plugin._start_async_check(self.parent, self.button, client, 'public thread test')
            self.pump_until(lambda: not self.plugin._active_checks)
        info.assert_called_once()
        self.assertEqual(self.plugin._check_contexts, {})

    def test_startup_result_without_an_input_button_reaches_main_thread_and_cleans_up(self):
        client = Mock()
        client.check_secret.return_value = LeakCheckResult(True, 3, None, MODE_K_ANONYMITY)
        with patch.object(self.plugin, '_startup_is_current', return_value=True), \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._start_async_check(self.parent, None, client,
                                           'public startup extension', startup=object())
            self.pump_until(lambda: not self.plugin._active_checks)
        warning.assert_called_once()
        self.assertEqual(self.plugin._check_contexts, {})

    def test_shutdown_cancels_and_joins_without_needing_queued_quit_delivery(self):
        started, released = Event(), Event()
        client = Mock()
        def check(secret):
            started.set()
            released.wait(timeout=0.2)
            return self.result
        client.check_secret.side_effect = check
        client.cancel.side_effect = released.set
        with patch.object(self.qt.QMessageBox, 'information') as info, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._start_async_check(self.parent, self.button, client, 'public cancellation test')
            self.pump_until(started.is_set)
            self.plugin._wait_for_shutdown()
            self.application.processEvents()
        client.cancel.assert_called_once()
        self.assertEqual(self.plugin._active_checks, [])
        self.assertEqual(self.plugin._check_contexts, {})
        info.assert_not_called()
        warning.assert_not_called()
