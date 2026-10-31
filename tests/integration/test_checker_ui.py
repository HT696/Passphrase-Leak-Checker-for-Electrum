"""Real offscreen Qt controls with Electrum stubs; no wallets or networking."""

import importlib
import os
import unittest
import weakref
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.integration import test_electrum_qt as qt_tests
from passphrase_leak_checker.client import LeakCheckResult, MODE_K_ANONYMITY, PwnedClient


@unittest.skipUnless(qt_tests.QT_AVAILABLE, 'Qt binding required for release validation')
class CheckerUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        qt_tests.PluginUITests.setUpClass()
        cls.qt = qt_tests.PluginUITests.qt
        cls.widgets = importlib.import_module(cls.qt.QLineEdit.__module__)
        with patch.dict(os.environ, {'QT_QPA_PLATFORM': 'offscreen'}):
            cls.application = cls.widgets.QApplication.instance() or cls.widgets.QApplication([])

    def setUp(self):
        self.plugin = self.qt.Plugin()
        self.window = self.widgets.QWidget()
        self.window.tools_menu = self.widgets.QMenu(self.window)
        self.window.wallet = SimpleNamespace(get_seed_type=lambda: 'segwit')
        self.forms = []
        # Host normalization requires separate validation.
        mnemonic = SimpleNamespace(normalize_text=Mock(side_effect=lambda text: text))
        self.host_rules = patch.dict('sys.modules', {'electrum.mnemonic': mnemonic})
        self.host_rules.start()
        self.addCleanup(self.host_rules.stop)

    def tearDown(self):
        self.plugin.close()
        for thread, worker in list(self.plugin._active_checks):
            self.plugin._on_thread_finished(thread, worker)
        for form in self.forms:
            form.hide()
            form.deleteLater()
        self.window.deleteLater()
        self.application.processEvents()

    def dialog(self, parent, title):
        dialog = self.widgets.QDialog(parent)
        dialog.setWindowTitle(title)
        return dialog

    def host_widget(self, name, module, parent=None, *, dialog=False):
        # Host fixtures with real Qt layouts and events. No Electrum wallet
        # is created, and no host validation is implied by these doubles.
        base = self.widgets.QDialog if dialog else self.widgets.QWidget
        widget = type(name, (base,), {'__module__': module})(parent)
        self.widgets.QVBoxLayout(widget)
        return widget

    def wizard_page(self, name='WCEnterExt'):
        wizard = self.widgets.QDialog()
        self.forms.append(wizard)
        self.widgets.QVBoxLayout(wizard)
        stack = self.widgets.QStackedWidget(wizard)
        wizard.layout().addWidget(stack)
        page = self.host_widget(name, 'electrum.gui.qt.wizard.wallet', stack)
        if name == 'WCEnterExt':
            page.wizard_data = {'seed_type': 'segwit'}
            page.wizard = SimpleNamespace(current_cosigner=lambda data: data)
            page.ext_edit = self.widgets.QWidget(page)
            self.widgets.QVBoxLayout(page.ext_edit)
            page.ext_edit.layout().addWidget(self.widgets.QLabel('Seed extension'))
            field = page.ext_edit.line = self.widgets.QLineEdit(page.ext_edit)
            page.ext_edit.layout().addWidget(field)
            page.layout().addWidget(page.ext_edit)
        else:
            grid = self.widgets.QGridLayout()
            field = self.widgets.QLineEdit(page)
            field.setEchoMode(self.widgets.QLineEdit.EchoMode.Password)
            confirmation = self.widgets.QLineEdit(page)
            grid.addWidget(self.widgets.QLabel('Password:'), 1, 0)
            grid.addWidget(field, 1, 1)
            grid.addWidget(confirmation, 2, 1)
            page.pw_layout = SimpleNamespace(new_pw=field, conf_pw=confirmation, grid=grid)
            page.layout().addLayout(grid)
        stack.addWidget(page)
        return wizard, stack, page, field

    def seed_popup(self, *, extension=True, label='Your seed extension is:', readonly=True):
        dialog = self.host_widget('SeedDialog', 'electrum.gui.qt.seed_dialog',
                                  getattr(self, 'window', None), dialog=True)
        self.forms.append(dialog)
        seed_widget = self.host_widget('SeedWidget', 'electrum.gui.qt.seed_dialog', dialog)
        dialog.layout().addWidget(seed_widget)
        mnemonic = self.widgets.QPlainTextEdit(seed_widget)
        mnemonic.setPlainText('public mnemonic fixture; never read by PassphraseLeakChecker')
        mnemonic.text = Mock(side_effect=AssertionError('Mnemonic read'))
        mnemonic.toPlainText = Mock(side_effect=AssertionError('Mnemonic read'))
        seed_widget.layout().addWidget(mnemonic)
        field = None
        if extension:
            row = self.widgets.QHBoxLayout()
            row.addWidget(self.widgets.QLabel(label))
            field = self.widgets.QLineEdit(seed_widget)
            field.setText('public extension fixture')
            field.setReadOnly(readonly)
            row.addWidget(field)
            seed_widget.layout().addLayout(row)
        return dialog, seed_widget, field, mnemonic

    def leak_buttons(self, widget):
        return [button for button in widget.findChildren(self.widgets.QPushButton, 'passphrase_leak_checker_check_leak')
                if not button.isHidden()]

    def test_tools_menu_opens_checker_and_does_not_duplicate_the_action(self):
        with patch.object(self.plugin, '_show_check_dialog') as show:
            self.plugin.init_menubar(self.window)
            self.plugin.init_menubar(self.window)
            actions = self.window.tools_menu.actions()
            self.assertEqual(len(actions), 1)
            self.assertEqual(actions[0].text(), 'Passphrase Leak Checker…')
            actions[0].trigger()
        show.assert_called_once_with(self.window)

    def test_disabling_plugin_removes_menu_action_and_prevents_readding_it(self):
        self.plugin.init_menubar(self.window)
        self.plugin.close()
        self.assertEqual(self.window.tools_menu.actions(), [])
        self.plugin.init_menubar(self.window)
        self.assertEqual(self.window.tools_menu.actions(), [])

    def test_rebuilding_a_windows_menu_moves_the_action_to_the_new_menu(self):
        self.plugin.init_menubar(self.window)
        old_menu = self.window.tools_menu
        self.window.tools_menu = self.widgets.QMenu(self.window)
        self.plugin.init_menubar(self.window)
        self.assertEqual(old_menu.actions(), [])
        self.assertEqual(len(self.window.tools_menu.actions()), 1)

    def test_original_password_hook_adds_a_working_button_beside_the_field(self):
        grid = self.widgets.QGridLayout(self.window)
        field = self.widgets.QLineEdit(self.window)
        grid.addWidget(field, 1, 1)
        with patch.object(self.plugin, '_on_check_button_clicked') as check:
            self.plugin.password_dialog(field, grid, 1)
            button = grid.itemAtPosition(1, 2).widget()
            self.assertEqual(button.text(), 'Check for Leaks')
            button.click()
        check.assert_called_once_with(field, button)

    def test_closing_one_window_keeps_other_windows_action(self):
        other = self.widgets.QWidget()
        other.tools_menu = self.widgets.QMenu(other)
        try:
            self.plugin.init_menubar(self.window)
            self.plugin.init_menubar(other)
            self.plugin.on_close_window(self.window)
            self.assertEqual(self.window.tools_menu.actions(), [])
            self.assertEqual(len(other.tools_menu.actions()), 1)
            self.plugin.on_close_window(other)
        finally:
            other.deleteLater()

    def test_checker_hides_input_and_click_uses_the_existing_lookup_handler(self):
        def execute(dialog):
            field = dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase')
            button = dialog.findChild(self.widgets.QPushButton, 'passphrase_leak_checker_check_leak')
            self.assertIsNotNone(field)
            self.assertIsNotNone(button)
            self.assertEqual(field.echoMode(), self.widgets.QLineEdit.EchoMode.Password)
            field.setText('public checker example')
            button.click()
            kind = dialog.findChild(self.widgets.QComboBox, 'passphrase_leak_checker_secret_kind')
            check.assert_called_once_with(field, button, kind_control=kind)
            return False
        with patch.object(self.qt, 'WindowModalDialog', side_effect=self.dialog), \
                patch.object(self.plugin, '_dialog_exec', side_effect=execute), \
                patch.object(self.plugin, '_on_check_button_clicked') as check:
            self.plugin._show_check_dialog(self.window)

    def test_opening_or_typing_in_checker_never_starts_a_lookup(self):
        def execute(dialog):
            field = dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase')
            self.assertEqual(field.text(), '')
            field.setText('public checker example')
            return False
        with patch.object(self.qt, 'WindowModalDialog', side_effect=self.dialog), \
                patch.object(self.plugin, '_dialog_exec', side_effect=execute), \
                patch.object(self.plugin, '_build_client') as build, \
                patch.object(self.plugin, '_start_async_check') as start:
            self.plugin._show_check_dialog(self.window)
        build.assert_not_called()
        start.assert_not_called()

    def test_closing_checker_clears_input_and_invalidates_its_pending_check(self):
        thread, worker = Mock(), Mock()
        captured = []
        def execute(dialog):
            field = dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase')
            button = dialog.findChild(self.widgets.QPushButton, 'passphrase_leak_checker_check_leak')
            field.setText('public checker example')
            captured.append(field)
            self.plugin._active_checks.append((thread, worker))
            self.plugin._check_contexts[thread] = {
                'parent': weakref.ref(dialog), 'button': weakref.ref(button),
                'valid': True, 'connections': [],
            }
            return False
        with patch.object(self.qt, 'WindowModalDialog', side_effect=self.dialog), \
                patch.object(self.plugin, '_dialog_exec', side_effect=execute):
            self.plugin._show_check_dialog(self.window)
        self.assertEqual(captured[0].text(), '')
        self.assertFalse(self.plugin._check_contexts[thread]['valid'])
        worker.cancel.assert_called_once()

    def test_seed_extension_wizard_adds_button_beside_original_field(self):
        wizard, stack, page, field = self.wizard_page()
        original_fields = page.findChildren(self.widgets.QLineEdit)
        wizard.show()
        self.application.processEvents()
        buttons = self.leak_buttons(page)
        self.assertEqual(len(buttons), 1)
        self.assertEqual(page.findChildren(self.widgets.QLineEdit), original_fields)
        row = page.ext_edit.layout().itemAt(1).layout()
        self.assertIs(row.itemAt(0).widget(), field)
        self.assertIs(row.itemAt(1).widget(), buttons[0])
        self.assertFalse(buttons[0].autoDefault())

    def test_wizard_check_uses_current_extension_without_extra_typing(self):
        wizard, stack, page, field = self.wizard_page()
        wizard.show()
        raw = '  PUBLIC existing extension  '
        field.setText(raw)
        data = dict(page.wizard_data)
        changed = Mock()
        field.textChanged.connect(changed)
        normalize = Mock(return_value='public existing extension')
        with patch.dict('sys.modules', {'electrum.mnemonic': SimpleNamespace(normalize_text=normalize)}), \
                patch.object(self.plugin, '_require_network_policy', return_value=None), \
                patch.object(self.plugin, '_build_client') as build, \
                patch.object(self.plugin, '_confirm_disclosure', return_value=True), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(page)[0].click()
        start.assert_called_once_with(parent=wizard, button=self.leak_buttons(page)[0],
                                     client=build.return_value, passphrase='public existing extension',
                                     source=field, kind_control=None)
        normalize.assert_called_once_with(raw)
        self.assertEqual(field.text(), raw)
        changed.assert_not_called()
        self.assertEqual(page.wizard_data, data)
        self.assertIs(stack.currentWidget(), page)

    def test_wallet_password_wizard_checks_new_password_field(self):
        wizard, stack, page, field = self.wizard_page('WCWalletPassword')
        wizard.show()
        field.setText('public new wallet password')
        with patch.object(self.plugin, '_on_check_button_clicked') as check:
            button = self.leak_buttons(page)[0]
            self.assertIs(page.pw_layout.grid.itemAtPosition(1, 2).widget(), button)
            button.click()
        check.assert_called_once_with(field, button)
        self.assertEqual(field.text(), 'public new wallet password')
        self.assertEqual(page.pw_layout.conf_pw.text(), '')
        self.assertEqual(len(page.findChildren(self.widgets.QLineEdit)), 2)

    def test_change_password_dialog_checks_new_password_not_current_or_confirmation(self):
        dialog = self.host_widget('ChangePasswordDialogForSW', 'electrum.gui.qt.password_dialog', dialog=True)
        self.forms.append(dialog)
        grid = self.widgets.QGridLayout()
        current, new, confirmation = [self.widgets.QLineEdit(dialog) for _ in range(3)]
        for row, field in enumerate((current, new, confirmation)):
            grid.addWidget(field, row, 1)
        dialog.playout = SimpleNamespace(new_pw=new, grid=grid)
        dialog.layout().addLayout(grid)
        dialog.show()
        with patch.object(self.plugin, '_on_check_button_clicked') as check:
            button = self.leak_buttons(dialog)[0]
            button.click()
        check.assert_called_once_with(new, button)

    def test_revisiting_wizard_page_does_not_duplicate_button(self):
        wizard, stack, page, field = self.wizard_page()
        next_page = self.widgets.QWidget(stack)
        stack.addWidget(next_page)
        wizard.show()
        for _ in range(3):
            stack.setCurrentWidget(next_page)
            stack.setCurrentWidget(page)
        self.assertEqual(len(self.leak_buttons(page)), 1)

    def test_leaving_wizard_page_cancels_and_suppresses_pending_result(self):
        wizard, stack, page, field = self.wizard_page()
        next_page = self.widgets.QWidget(stack)
        stack.addWidget(next_page)
        wizard.show()
        button = self.leak_buttons(page)[0]
        thread, worker = Mock(), Mock()
        self.plugin._active_checks.append((thread, worker))
        self.plugin._check_contexts[thread] = {
            'parent': weakref.ref(wizard), 'button': weakref.ref(button),
            'valid': True, 'connections': [],
        }
        stack.setCurrentWidget(next_page)
        self.assertFalse(self.plugin._check_contexts[thread]['valid'])
        worker.cancel.assert_called_once()
        with patch.object(self.qt.QMessageBox, 'information') as info, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.plugin._on_async_check_finished(wizard, button, thread, worker, None, 'unavailable')
        info.assert_not_called()
        warning.assert_not_called()

    def test_page_hidden_during_disclosure_cannot_start_lookup(self):
        wizard, stack, page, field = self.wizard_page()
        wizard.show()
        field.setText('public extension')
        def disclose(parent, client):
            page.hide()
            return True
        with patch.object(self.plugin, '_require_network_policy', return_value=None), \
                patch.object(self.plugin, '_build_client'), \
                patch.object(self.plugin, '_confirm_disclosure', side_effect=disclose), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(page)[0].click()
        start.assert_not_called()

    def test_seed_popup_reuses_readonly_extension_and_never_reads_mnemonic(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup()
        with patch.object(self.plugin, '_on_check_button_clicked') as check:
            dialog.show()
            buttons = self.leak_buttons(dialog)
            self.assertEqual(len(buttons), 1)
            buttons[0].click()
        check.assert_called_once_with(field, buttons[0])
        mnemonic.text.assert_not_called()
        mnemonic.toPlainText.assert_not_called()
        self.assertEqual(len(dialog.findChildren(self.widgets.QLineEdit)), 1)

    def test_seed_popup_without_extension_has_no_check_button(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup(extension=False)
        dialog.show()
        self.assertEqual(self.leak_buttons(dialog), [])
        mnemonic.text.assert_not_called()
        mnemonic.toPlainText.assert_not_called()

    def test_seed_popup_unknown_or_editable_row_is_not_used_as_extension(self):
        for options in ({'label': 'Some other field:'}, {'readonly': False}):
            with self.subTest(options=options):
                dialog, seed_widget, field, mnemonic = self.seed_popup(**options)
                dialog.show()
                self.assertEqual(self.leak_buttons(dialog), [])

    def test_seed_popup_extension_label_uses_host_translation(self):
        translate = lambda text: 'translated' if text == 'Your seed extension is' else text
        with patch.dict(self.qt.InlineControls._add_seed_extension.__globals__, {'_': translate}):
            dialog, seed_widget, field, mnemonic = self.seed_popup(label='translated:')
            dialog.show()
            self.assertEqual(len(self.leak_buttons(dialog)), 1)

    def test_opening_forms_and_typing_never_reads_inputs_or_starts_checks(self):
        wizard, stack, page, field = self.wizard_page()
        dialog, seed_widget, extension, mnemonic = self.seed_popup()
        with patch.object(field, 'text', side_effect=AssertionError('Input read before click')), \
                patch.object(extension, 'text', side_effect=AssertionError('Input read before click')), \
                patch.object(self.plugin, '_build_client') as build, \
                patch.object(self.plugin, '_start_async_check') as start:
            wizard.show()
            dialog.show()
            field.setText('public edited extension')
            self.application.processEvents()
        build.assert_not_called()
        start.assert_not_called()

    def test_unrelated_widget_with_same_class_name_is_left_alone(self):
        widget = self.host_widget('WCEnterExt', 'another_application')
        self.forms.append(widget)
        widget.ext_edit = self.widgets.QWidget(widget)
        self.widgets.QVBoxLayout(widget.ext_edit)
        widget.ext_edit.line = self.widgets.QLineEdit(widget.ext_edit)
        widget.ext_edit.layout().addWidget(widget.ext_edit.line)
        widget.layout().addWidget(widget.ext_edit)
        widget.show()
        self.assertEqual(self.leak_buttons(widget), [])

    def test_disable_restores_extension_layout_and_keeps_host_field_and_signals(self):
        wizard, stack, page, field = self.wizard_page()
        changed = Mock()
        field.textChanged.connect(changed)
        field.setText('public original extension')
        wizard.show()
        self.plugin.close()
        self.assertEqual(self.leak_buttons(page), [])
        self.assertIs(page.ext_edit.layout().itemAt(1).widget(), field)
        self.assertEqual(field.text(), 'public original extension')
        field.setText('public revised extension')
        self.assertEqual(changed.call_count, 2)
        page.hide()
        page.show()
        self.assertEqual(self.leak_buttons(page), [])

    def test_enable_plugin_while_form_is_already_visible(self):
        self.plugin.close()
        wizard, stack, page, field = self.wizard_page()
        wizard.show()
        self.assertEqual(self.leak_buttons(page), [])
        self.plugin = self.qt.Plugin()
        self.assertEqual(len(self.leak_buttons(page)), 1)

    def test_unsupported_host_layout_never_crashes_host_events(self):
        wizard, stack, page, field = self.wizard_page()
        with patch.object(page.ext_edit, 'layout', side_effect=RuntimeError('unsupported host')):
            wizard.show()
        self.assertEqual(self.leak_buttons(page), [])

    def test_seed_word_pages_and_extension_confirmation_are_left_alone(self):
        for name in ('WCCreateSeed', 'WCHaveSeed', 'WCConfirmSeed', 'WCConfirmExt'):
            with self.subTest(page=name):
                page = self.host_widget(name, 'electrum.gui.qt.wizard.wallet')
                self.forms.append(page)
                field = self.widgets.QLineEdit(page)
                page.layout().addWidget(field)
                field.text = Mock(side_effect=AssertionError('Unexpected input read'))
                page.show()
                self.assertEqual(self.leak_buttons(page), [])
                field.text.assert_not_called()

    def test_password_button_never_overwrites_an_occupied_host_grid_cell(self):
        wizard, stack, page, field = self.wizard_page('WCWalletPassword')
        existing = self.widgets.QPushButton('Host control', page)
        page.pw_layout.grid.addWidget(existing, 1, 2)
        wizard.show()
        self.assertEqual(self.leak_buttons(page), [])
        self.assertIs(page.pw_layout.grid.itemAtPosition(1, 2).widget(), existing)

    def test_disable_removes_popup_button_and_preserves_displayed_extension(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup()
        dialog.show()
        self.assertEqual(len(self.leak_buttons(dialog)), 1)
        self.plugin.close()
        self.assertEqual(self.leak_buttons(dialog), [])
        row = seed_widget.layout().itemAt(1).layout()
        self.assertEqual(row.count(), 2)
        self.assertIs(row.itemAt(1).widget(), field)
        self.assertEqual(field.text(), 'public extension fixture')

    def test_reopening_seed_popup_does_not_duplicate_its_control(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup()
        for _ in range(3):
            dialog.show()
            dialog.hide()
        dialog.show()
        self.assertEqual(len(self.leak_buttons(dialog)), 1)

    def test_deleting_form_before_disabling_plugin_does_not_break_cleanup(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup()
        dialog.show()
        dialog.deleteLater()
        core = importlib.import_module(self.qt.QObject.__module__)
        self.application.sendPostedEvents(None, core.QEvent.Type.DeferredDelete)
        self.forms.remove(dialog)
        self.plugin.close()

    def test_inline_extension_sends_host_normalized_value_and_keeps_original_field(self):
        wizard, stack, page, field = self.wizard_page()
        field.setText('  PASSWORD  ')
        wizard.show()
        normalize = Mock(return_value='password')
        with patch.dict('sys.modules', {'electrum.mnemonic': SimpleNamespace(normalize_text=normalize)}), \
                patch.object(self.plugin, '_require_network_policy'), \
                patch.object(self.plugin, '_build_client') as build, \
                patch.object(self.plugin, '_confirm_disclosure', return_value=True), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(page)[0].click()
        normalize.assert_called_once_with('  PASSWORD  ')
        self.assertEqual(start.call_args.kwargs['passphrase'], 'password')
        self.assertIn('Electrum-normalized', build.return_value.secret_description)
        self.assertEqual(field.text(), '  PASSWORD  ')

    def test_cosigner_extension_uses_host_current_cosigner_metadata(self):
        wizard, stack, page, field = self.wizard_page()
        page.wizard.current_cosigner = Mock(return_value={'seed_type': 'bip39'})
        field.setText('café')
        wizard.show()
        normalize = Mock(return_value='cafe\u0301')
        with patch.dict('sys.modules', {'electrum.keystore': SimpleNamespace(bip39_normalize_passphrase=normalize)}), \
                patch.object(self.plugin, '_require_network_policy'), \
                patch.object(self.plugin, '_build_client'), \
                patch.object(self.plugin, '_confirm_disclosure', return_value=True), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(page)[0].click()
        self.assertEqual(start.call_args.kwargs['passphrase'], 'cafe\u0301')
        page.wizard.current_cosigner.assert_called_with(page.wizard_data)

    def test_seed_popup_gets_format_from_wallet_metadata_without_reading_mnemonic(self):
        dialog, seed_widget, field, mnemonic = self.seed_popup()
        self.window.wallet.get_seed_type = Mock(return_value='slip39')
        dialog.show()
        with patch.object(self.plugin, '_require_network_policy'), \
                patch.object(self.plugin, '_build_client'), \
                patch.object(self.plugin, '_confirm_disclosure', return_value=True), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(dialog)[0].click()
        self.assertEqual(start.call_args.kwargs['passphrase'], field.text())
        self.window.wallet.get_seed_type.assert_called()
        mnemonic.toPlainText.assert_not_called()

    def test_unknown_inline_extension_format_is_refused_before_consent_or_client(self):
        wizard, stack, page, field = self.wizard_page()
        page.wizard_data.clear()
        field.setText('public extension')
        wizard.show()
        with patch.object(self.plugin, '_build_client') as build, \
                patch.object(self.plugin, '_confirm_disclosure') as consent, \
                patch.object(self.qt.QMessageBox, 'warning') as warning:
            self.leak_buttons(page)[0].click()
        build.assert_not_called()
        consent.assert_not_called()
        self.assertIn('seed format', warning.call_args.args[2])

    def test_format_change_during_consent_cannot_start_check_of_old_effective_value(self):
        wizard, stack, page, field = self.wizard_page()
        field.setText('public extension')
        wizard.show()
        def consent(*args):
            page.wizard_data['seed_type'] = 'bip39'
            return True
        with patch.object(self.plugin, '_require_network_policy'), \
                patch.object(self.plugin, '_build_client'), \
                patch.object(self.plugin, '_confirm_disclosure', side_effect=consent), \
                patch.object(self.plugin, '_start_async_check') as start:
            self.leak_buttons(page)[0].click()
        start.assert_not_called()

    def test_manual_checker_forwards_explicit_seed_format(self):
        def execute(dialog):
            field = dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase')
            combo = dialog.findChild(self.widgets.QComboBox, 'passphrase_leak_checker_secret_kind')
            combo.setCurrentIndex(combo.findData('bip39'))
            field.setText('public extension')
            self.leak_buttons(dialog)[0].click()
            check.assert_called_once_with(field, self.leak_buttons(dialog)[0], kind_control=combo)
            return False
        with patch.object(self.qt, 'WindowModalDialog', side_effect=self.dialog), \
                patch.object(self.plugin, '_dialog_exec', side_effect=execute), \
                patch.object(self.plugin, '_on_check_button_clicked') as check:
            self.plugin._show_check_dialog(self.window)

    def pending_manual(self, execute, *, consent=None):
        """Check control ownership while a worker is pending."""
        thread, worker = Mock(), Mock()
        thread.isRunning.return_value = True
        client = PwnedClient('https://example.invalid/{prefix}')
        with patch.object(self.qt, 'WindowModalDialog', side_effect=self.dialog), \
                patch.object(self.qt, 'QThread', return_value=thread), \
                patch.object(self.qt, '_LeakCheckWorker', return_value=worker) as factory, \
                patch.object(self.plugin, '_require_network_policy', return_value=None), \
                patch.object(self.plugin, '_build_client', return_value=client), \
                patch.object(self.plugin, '_confirm_disclosure', side_effect=consent or (lambda *args: True)), \
                patch.object(self.plugin, '_dialog_exec', side_effect=lambda dialog: execute(dialog, thread, worker)):
            self.plugin._show_check_dialog(self.window)
        return factory

    def test_manual_type_change_cancels_and_suppresses_old_no_match_even_after_changing_back(self):
        def execute(dialog, thread, worker):
            field = dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase')
            combo = dialog.findChild(self.widgets.QComboBox, 'passphrase_leak_checker_secret_kind')
            button = self.leak_buttons(dialog)[0]
            field.setText('  PASSWORD  ')
            button.click()
            self.assertTrue(self.plugin._check_contexts[thread]['valid'])
            combo.setCurrentIndex(combo.findData('electrum'))
            self.assertFalse(self.plugin._check_contexts[thread]['valid'])
            worker.cancel.assert_called_once()
            combo.setCurrentIndex(combo.findData(None))
            self.assertFalse(self.plugin._check_contexts[thread]['valid'])
            result = LeakCheckResult(False, 0, None, MODE_K_ANONYMITY)
            with patch.object(self.qt.QMessageBox, 'information') as info, \
                    patch.object(self.qt.QMessageBox, 'warning') as warning:
                self.plugin._on_async_check_finished(dialog, button, thread, worker, result, None)
            info.assert_not_called()
            warning.assert_not_called()
            return False
        factory = self.pending_manual(execute)
        self.assertEqual(factory.call_args.kwargs['passphrase'], '  PASSWORD  ')

    def test_manual_type_changed_during_consent_never_starts_old_lookup(self):
        def consent(dialog, client):
            combo = dialog.findChild(self.widgets.QComboBox, 'passphrase_leak_checker_secret_kind')
            combo.setCurrentIndex(combo.findData('electrum'))
            return True
        def execute(dialog, thread, worker):
            dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase').setText('public password')
            self.leak_buttons(dialog)[0].click()
            self.assertEqual(self.plugin._active_checks, [])
            return False
        factory = self.pending_manual(execute, consent=consent)
        factory.assert_not_called()

    def test_result_identifies_the_captured_value_type(self):
        def execute(dialog, thread, worker):
            dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase').setText('public password')
            button = self.leak_buttons(dialog)[0]
            button.click()
            result = LeakCheckResult(False, 0, None, MODE_K_ANONYMITY)
            with patch.object(self.qt.QMessageBox, 'information') as info:
                self.plugin._on_async_check_finished(dialog, button, thread, worker, result, None)
            message = info.call_args.args[2]
            self.assertIn('The wallet password is checked exactly as entered.', message)
            self.assertNotIn('public password', message)
            return False
        self.pending_manual(execute)

    def test_thread_completion_disconnects_manual_type_listeners(self):
        def execute(dialog, thread, worker):
            dialog.findChild(self.widgets.QLineEdit, 'passphrase_leak_checker_passphrase').setText('public password')
            self.leak_buttons(dialog)[0].click()
            self.plugin._on_thread_finished(thread, worker)
            combo = dialog.findChild(self.widgets.QComboBox, 'passphrase_leak_checker_secret_kind')
            combo.setCurrentIndex(combo.findData('electrum'))
            worker.cancel.assert_not_called()
            self.assertEqual(self.plugin._check_contexts, {})
            return False
        self.pending_manual(execute)
