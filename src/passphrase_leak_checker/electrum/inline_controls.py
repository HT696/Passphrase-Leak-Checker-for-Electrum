"""Attach manual checks to specific Electrum fields without reading seed words.

Electrum has no hook for its seed popup or these wizard pages. Observe their
Show events instead of replacing host classes or changing wizard navigation.
Unknown host layouts are left alone. Inspecting a form never reads its inputs.
"""

import weakref

from electrum.i18n import _

try:
    from PyQt6.QtCore import QEvent, QObject
    from PyQt6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout
except ImportError:
    from PyQt5.QtCore import QEvent, QObject
    from PyQt5.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout


class InlineControls(QObject):
    def __init__(self, application, check, cancel):
        super().__init__()
        self._application = None
        self._check = check
        self._cancel = cancel
        self._controls = weakref.WeakKeyDictionary()
        self._closed = False
        self.bind_application(application)

    def bind_application(self, application):
        # Enabled plugins are constructed before Electrum creates QApplication.
        # GUI hooks retry this once the host application is available.
        if self._closed or application is None or application is self._application:
            return
        if self._application is not None:
            self._application.removeEventFilter(self)
        self._application = application
        application.installEventFilter(self)
        # Enabling the plugin can happen while a supported form is open.
        for widget in getattr(application, 'allWidgets', lambda: [])():
            try:
                if widget.isVisible():
                    self._attach_for_widget(widget)
            except Exception:
                pass

    def eventFilter(self, watched, event):
        if not self._closed:
            try:
                if event.type() == QEvent.Type.Show:
                    self._attach_for_widget(watched)
                elif event.type() == QEvent.Type.Hide:
                    for record in list(self._controls.values()):
                        if record['scope']() is watched:
                            button = record['button']()
                            if button is not None:
                                self._cancel(button)
            except Exception:
                # Exceptions escaping a Qt event filter can terminate the host.
                # Keep unsupported or deleted forms from affecting wallet operations.
                pass
        return False

    def _attach_for_widget(self, widget):
        identity = (type(widget).__module__, type(widget).__name__)
        if identity == ('electrum.gui.qt.wizard.wallet', 'WCEnterExt'):
            editor = getattr(widget, 'ext_edit', None)
            field = getattr(editor, 'line', None)
            if isinstance(field, QLineEdit):
                self.add(field, editor.layout(), widget, extension=True)
        elif identity == ('electrum.gui.qt.wizard.wallet', 'WCWalletPassword'):
            self._add_password_layout(getattr(widget, 'pw_layout', None), widget)
        elif identity in {
            ('electrum.gui.qt.password_dialog', 'ChangePasswordDialogForSW'),
            ('electrum.gui.qt.password_dialog', 'NewPasswordDialog'),
        }:
            self._add_password_layout(getattr(widget, 'playout', None), widget)
        elif identity == ('electrum.gui.qt.seed_dialog', 'SeedDialog'):
            self._add_seed_extension(widget)

    def _add_password_layout(self, password_layout, scope):
        field = getattr(password_layout, 'new_pw', None)
        grid = getattr(password_layout, 'grid', None)
        if isinstance(field, QLineEdit) and isinstance(grid, QGridLayout):
            self.add(field, grid, scope)

    def _add_seed_extension(self, dialog):
        layout = dialog.layout()
        if layout is None:
            return
        for index in range(layout.count()):
            widget = layout.itemAt(index).widget()
            if (type(widget).__module__, type(widget).__name__) != (
                'electrum.gui.qt.seed_dialog', 'SeedWidget'
            ):
                continue
            seed_layout = widget.layout()
            if seed_layout is None:
                continue
            for row_index in range(seed_layout.count()):
                row = seed_layout.itemAt(row_index).layout()
                if not isinstance(row, QHBoxLayout) or row.count() < 2:
                    continue
                label, field = row.itemAt(0).widget(), row.itemAt(1).widget()
                # Match the host's dedicated extension row, never its mnemonic
                # editor, another text field, or the wallet's keystore data.
                if (isinstance(label, QLabel) and label.text() == _('Your seed extension is') + ':'
                        and isinstance(field, QLineEdit) and field.isReadOnly()):
                    self.add(field, row, dialog, extension=True)

    def add(self, field, layout, scope, *, extension=False):
        if self._closed or field in self._controls or layout is None:
            return
        index = layout.indexOf(field)
        if index < 0:
            return
        wrapper = None
        if isinstance(layout, QGridLayout):
            row, column, height, width = layout.getItemPosition(index)
            if height != 1 or layout.itemAtPosition(row, column + width) is not None:
                return
        elif not isinstance(layout, (QHBoxLayout, QVBoxLayout)):
            return

        button = QPushButton(_('Check for Leaks'), scope)
        button.setObjectName('passphrase_leak_checker_check_leak')
        button.setToolTip(_('Check this password or seed extension. Do not paste recovery-seed words.'))
        # Preserve Enter's normal action.
        button.setAutoDefault(False)
        button.setDefault(False)
        source_ref, button_ref = weakref.ref(field), weakref.ref(button)

        def clicked(checked=False):
            source, control = source_ref(), button_ref()
            if not self._closed and source is not None and control is not None:
                self._check(source, control)

        button.clicked.connect(clicked)
        if isinstance(layout, QGridLayout):
            layout.addWidget(button, row, column + width)
        elif isinstance(layout, QHBoxLayout):
            layout.insertWidget(index + 1, button)
        else:
            # Keep the original editor and all its host signal connections.
            layout.takeAt(index)
            wrapper = QHBoxLayout()
            wrapper.addWidget(field)
            wrapper.addWidget(button)
            layout.insertLayout(index, wrapper)
        self._controls[field] = {
            'scope': weakref.ref(scope), 'button': button_ref,
            'layout': weakref.ref(layout),
            'extension': extension,
            'wrapper': weakref.ref(wrapper) if wrapper is not None else lambda: None,
        }
        button.show()

    def seed_type(self, field):
        record = self._controls.get(field)
        if record is None or not record['extension']:
            return None  # Wallet passwords preserve exact text.
        scope = record['scope']()
        try:
            if type(scope).__name__ == 'WCEnterExt':
                data = scope.wizard.current_cosigner(scope.wizard_data)
                return data.get('seed_type') or 'unknown'
            parent = scope.parentWidget()
            return parent.wallet.get_seed_type() or 'unknown'
        except Exception:
            return 'unknown'

    def is_available(self, field):
        record = self._controls.get(field)
        if record is None:
            return True
        try:
            scope = record['scope']()
            return scope is not None and scope.isVisible() and field.isVisible()
        except RuntimeError:
            return False

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._application is not None:
            self._application.removeEventFilter(self)
            self._application = None
        for field, record in list(self._controls.items()):
            button = record['button']()
            layout, wrapper = record['layout'](), record['wrapper']()
            try:
                if button is not None:
                    self._cancel(button)
                    button.clicked.disconnect()
                    button.hide()
                    container = wrapper if wrapper is not None else layout
                    if container is not None:
                        container.removeWidget(button)
                    button.deleteLater()
                if wrapper is not None and layout is not None and wrapper.count() == 1:
                    index = layout.indexOf(wrapper)
                    if index >= 0 and wrapper.itemAt(0).widget() is field:
                        wrapper.removeWidget(field)
                        layout.takeAt(index)
                        layout.insertWidget(index, field)
                        wrapper.deleteLater()
            except (RuntimeError, TypeError):
                pass
        self._controls.clear()
        self._check = self._cancel = None
