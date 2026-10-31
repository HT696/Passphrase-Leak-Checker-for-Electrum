"""Reproduce Electrum's plugin-before-QApplication startup in fresh processes."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.integration import test_electrum_qt as qt_tests


ROOT = Path(__file__).resolve().parents[2]
STARTUP_CHECK = r'''
import importlib
import os
import sys

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
sys.path.insert(0, sys.argv[1])
if sys.argv[3] == 'qt5':
    sys.modules['PyQt6'] = None
from scripts.test import forbid_network
from tests.integration.test_electrum_qt import PluginUITests
from tests.integration.test_checker_ui import CheckerUITests

with forbid_network():
    PluginUITests.setUpClass()
    qt = PluginUITests.qt
    assert qt.QCoreApplication.instance() is None, 'Must start without QApplication'
    plugin = qt.Plugin()
    widgets = importlib.import_module(qt.QLineEdit.__module__)
    app = widgets.QApplication([])
    forms = CheckerUITests()
    forms.qt, forms.widgets, forms.application = qt, widgets, app
    forms.plugin, forms.forms = plugin, []
    wizard, stack, page, field = forms.wizard_page()
    window = widgets.QWidget()
    window.tools_menu = widgets.QMenu(window)
    try:
        if sys.argv[2] == 'wizard':
            # The wallet wizard can precede the first wallet window.
            plugin.init_wallet_wizard(wizard)
            plugin.init_wallet_wizard(wizard)
        else:
            plugin.init_menubar(window)
            plugin.init_menubar(window)
        wizard.show()
        popup, seed_widget, extension, mnemonic = forms.seed_popup()
        popup.show()
        app.processEvents()
        assert len(forms.leak_buttons(page)) == 1, 'First wizard has no inline check'
        assert len(forms.leak_buttons(popup)) == 1, 'Seed popup has no inline check'
        assert field.text() == '', 'Startup changed the host field'
        mnemonic.text.assert_not_called()
        mnemonic.toPlainText.assert_not_called()
        # Shutdown cancellation must also be connected after deferred startup.
        app.aboutToQuit.emit()
        assert plugin._closing, 'Deferred startup missed the shutdown connection'
        assert forms.leak_buttons(page) == [], 'Shutdown left an inline button'
    finally:
        plugin.close()
        for form in forms.forms:
            form.hide()
            form.deleteLater()
        window.deleteLater()
        app.processEvents()
'''


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class QtStartupTests(unittest.TestCase):
    def check_startup(self, first_hook):
        # Run each QApplication lifecycle in a separate process.
        # The child uses synthetic widgets with DNS and sockets blocked.
        qt5 = sys.modules.get('PyQt6', object()) is None
        with tempfile.TemporaryDirectory(prefix='passphrase_leak_checker-qt-startup-') as directory:
            result = subprocess.run(
                [sys.executable, '-I', '-B', '-c', STARTUP_CHECK, str(ROOT), first_hook,
                 'qt5' if qt5 else 'default'],
                cwd=directory, capture_output=True, text=True, timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_first_wallet_wizard_attaches_when_plugin_loaded_before_application(self):
        self.check_startup('wizard')

    def test_wallet_menu_attaches_when_plugin_loaded_before_application(self):
        self.check_startup('menu')
