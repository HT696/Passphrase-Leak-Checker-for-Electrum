import json
import weakref
from functools import partial
from typing import Dict

from electrum.i18n import _
from electrum.plugin import BasePlugin, hook

from .network_policy import get_network_proxy
from .inline_controls import InlineControls
from .http_transport import ElectrumHttpTransport
from .secret_policy import prepare_secret
from .pwned_api import (
    MODE_FULL_HASH,
    MODE_K_ANONYMITY,
    LeakCheckError,
    LeakCheckOutcome,
    PwnedClient,
    lookup_outcome,
)

try:
    from PyQt6.QtCore import QCoreApplication, QObject, QThread, QTimer, Qt, pyqtSignal
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSpinBox,
        QVBoxLayout,
    )
except ImportError:
    from PyQt5.QtCore import QCoreApplication, QObject, QThread, QTimer, Qt, pyqtSignal
    from PyQt5.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFormLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSpinBox,
        QVBoxLayout,
    )

from electrum.gui.qt.util import Buttons, CancelButton, EnterButton, OkButton, WindowModalDialog

# Keep a disabled plugin alive until its worker threads have actually stopped.
_CLOSING_PLUGINS = set()
_DIRECT_CONNECTION = getattr(Qt, 'DirectConnection', None)
if _DIRECT_CONNECTION is None:
    _DIRECT_CONNECTION = Qt.ConnectionType.DirectConnection


class _LeakCheckWorker(QObject):
    finished = pyqtSignal(object, object)

    def __init__(self, client: PwnedClient, passphrase: str):
        super().__init__()
        self._client = client
        self._passphrase = passphrase

    def run(self) -> None:
        try:
            result = self._client.check_secret(self._passphrase)
            self.finished.emit(result, None)
        except LeakCheckError:
            self.finished.emit(None, _("Could not check for leaks. Check the service URL and Electrum's network settings."))
        except Exception:
            self.finished.emit(None, _("Could not check for leaks because of an unexpected error."))
        finally:
            self._passphrase = None

    def cancel(self):
        self._client.cancel()


class _MainThreadInvoker(QObject):
    result_ready = pyqtSignal(object, object, object, object)
    thread_done = pyqtSignal(object, object)

    def __init__(self, plugin):
        super().__init__()
        self._plugin = plugin
        self.result_ready.connect(self._dispatch)
        self.thread_done.connect(self._plugin._on_thread_finished)

    def _dispatch(self, thread, worker, result, error_text) -> None:
        context = self._plugin._check_contexts.get(thread)
        if context is not None:
            self._plugin._on_async_check_finished(context['parent'](), context['button'](),
                                                 thread, worker, result, error_text)


class Plugin(BasePlugin):
    CFG_ENDPOINT = "endpoint_template"
    CFG_MODE = "lookup_mode"
    CFG_TIMEOUT = "timeout_seconds"
    CFG_HEADERS_JSON = "headers_json"
    CFG_CHECK_EXTENSION_ON_STARTUP = "check_extension_on_startup"
    CFG_STARTUP_APPROVAL = "startup_disclosure_approval"

    DEFAULT_ENDPOINT = "https://api.pwnedpasswords.com/range/{prefix}"
    DEFAULT_MODE = MODE_K_ANONYMITY
    DEFAULT_TIMEOUT_SECONDS = 7
    DEFAULT_HEADERS_JSON = '{"Add-Padding":"true"}'
    DEFAULT_CHECK_EXTENSION_ON_STARTUP = False
    MAX_ACTIVE_CHECKS = 4

    MODE_LABELS = (
        (MODE_K_ANONYMITY, "First 5 hash characters (recommended)"),
        (MODE_FULL_HASH, "Full hash (less private)"),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._active_checks = []
        self._check_contexts = {}
        self._closing = False
        self._settings_error = False
        self._menu_actions = weakref.WeakKeyDictionary()
        self._checker_dialogs = weakref.WeakSet()
        self._startup_checks = weakref.WeakKeyDictionary()
        self._ui_invoker = _MainThreadInvoker(self)
        self._application = None
        self._inline_controls = InlineControls(
            None, lambda field, button: self._on_check_button_clicked(field, button),
            self._cancel_button_check,
        )
        self._ensure_application()

    def _ensure_application(self):
        if self._closing:
            return
        application = QCoreApplication.instance()
        if application is None:
            return
        if application is not self._application:
            self._application = application
            application.aboutToQuit.connect(self._wait_for_shutdown)
        self._inline_controls.bind_application(application)

    @hook
    def init_wallet_wizard(self, wizard):
        # The wizard can open before the first wallet window.
        self._ensure_application()

    @hook
    def load_wallet(self, wallet, window):
        if self._closing or not self._startup_enabled():
            return
        previous = self._startup_checks.get(window)
        if previous is not None and previous[0] == id(wallet):
            return
        # Defer out of the wallet-load hook until Qt services the window. Store no
        # wallet, password or extension in the queued callback.
        self._ensure_application()
        state = (id(wallet), object())
        self._startup_checks[window] = state
        reference = weakref.ref(window)
        QTimer.singleShot(0, partial(self._check_extension_on_startup, reference, state))

    def _startup_enabled(self):
        try:
            if (self._settings_error or self._cfg_get(self.CFG_CHECK_EXTENSION_ON_STARTUP,
                                                    self.DEFAULT_CHECK_EXTENSION_ON_STARTUP) is not True):
                return False
            return self._startup_approval_matches(self._build_client())
        except Exception:
            return False

    @staticmethod
    def _startup_approval_for(client):
        # Bind ongoing approval to the complete service template, sharing mode
        # and outgoing privacy headers. Keep wallet data and secrets out of approval.
        return {'version': 1, 'endpoint_template': client.endpoint_template,
                'lookup_mode': client.mode, 'headers': dict(client.extra_headers)}

    def _startup_approval_matches(self, client):
        approval = self._cfg_get(self.CFG_STARTUP_APPROVAL)
        return (type(approval) is dict and type(approval.get('version')) is int
                and approval == self._startup_approval_for(client))

    def _startup_is_current(self, window, state):
        try:
            return (not self._closing and self._startup_enabled() and window is not None
                    and self._startup_checks.get(window) is state
                    and id(window.wallet) == state[0] and window.isVisible())
        except (AttributeError, RuntimeError, TypeError):
            return False

    def _check_extension_on_startup(self, reference, state):
        window = reference()
        password = passphrase = effective = None
        try:
            if not self._startup_is_current(window, state) or len(self._active_checks) >= self.MAX_ACTIVE_CHECKS:
                return
            wallet = window.wallet
            if not wallet.has_seed():
                return  # Only wallets with a local seed have an extension to check.
            proxy = self._require_network_policy()
            client = self._build_client(proxy=proxy)
            seed_type = wallet.get_seed_type()
            if not seed_type:
                raise LeakCheckError('Cannot determine the seed format.')
            # Read only an already-unlocked extension. Never prompt, unlock the
            # wallet, change its password caching, or retrieve recovery words.
            if wallet.has_keystore_encryption():
                password = wallet.get_unlocked_password()
                if password is None:
                    return
            if not self._startup_is_current(window, state):
                return
            passphrase = wallet.get_keystore().get_passphrase(password)
            password = None
            if not passphrase:
                return
            effective, description = prepare_secret(passphrase, seed_type)
            passphrase = None
            client.secret_description = description
            if not self._startup_approval_matches(client):
                return
            if client.mode == MODE_FULL_HASH:
                client.approve_full_hash_disclosure(client.destination)
            if not self._startup_is_current(window, state) or wallet.get_seed_type() != seed_type:
                return
            self._require_network_route(proxy)
            self._start_async_check(parent=window, button=None, client=client,
                                    passphrase=effective, startup=state)
        except Exception:
            # Startup is silent unless a valid leak match is returned. Host
            # errors may contain private diagnostics, so do not log them.
            pass
        finally:
            password = passphrase = effective = None

    def requires_settings(self):
        return True

    def close(self):
        if self._closing:
            return
        self._closing = True
        self._startup_checks.clear()
        self._inline_controls.close()
        for window in list(self._menu_actions):
            self._remove_menu_action(window)
        for dialog in list(self._checker_dialogs):
            try:
                dialog.reject()
            except RuntimeError:
                pass
        if self._active_checks:
            _CLOSING_PLUGINS.add(self)
        for thread, worker in list(self._active_checks):
            try:
                worker.cancel()
            except Exception:
                # A cancellation error is not evidence of thread termination.
                pass
            try:
                thread.quit()
                if not thread.isRunning():
                    self._on_thread_finished(thread, worker)
            except RuntimeError:
                self._on_thread_finished(thread, worker)
        self._release_closed_plugin()
        super_close = getattr(super(), "close", None)
        if callable(super_close):
            super_close()

    def _wait_for_shutdown(self):
        self.close()
        # Cancellation shuts down sockets and interrupts the bounded DNS wait.
        # Join before QApplication teardown; queued GUI callbacks are suppressed.
        for thread, worker in list(self._active_checks):
            thread.quit()
            if thread.wait():
                self._on_thread_finished(thread, worker)

    def _release_closed_plugin(self):
        if self._closing and not self._active_checks:
            _CLOSING_PLUGINS.discard(self)
            if self._application is not None:
                try:
                    self._application.aboutToQuit.disconnect(self._wait_for_shutdown)
                except (RuntimeError, TypeError):
                    pass
                self._application = None

    def settings_dialog(self, window):
        self._show_settings_dialog(window)

    @hook
    def init_menubar(self, window):
        if self._closing:
            return
        self._ensure_application()
        menu = getattr(window, 'tools_menu', None)
        if menu is None:
            return
        previous = self._menu_actions.get(window)
        if previous is not None:
            if previous[0]() is menu:
                return
            self._remove_menu_action(window)
        action = menu.addAction(_("Passphrase Leak Checker…"))
        reference = weakref.ref(window)
        def open_checker(checked=False):
            parent = reference()
            if parent is not None and not self._closing:
                self._show_check_dialog(parent)
        action.triggered.connect(open_checker)
        self._menu_actions[window] = (weakref.ref(menu), action)

    @hook
    def on_close_window(self, window):
        self._startup_checks.pop(window, None)
        for thread, context in list(self._check_contexts.items()):
            if context['parent']() is window:
                self._invalidate_check(thread)
        self._remove_menu_action(window)

    def _remove_menu_action(self, window):
        previous = self._menu_actions.pop(window, None)
        if previous is None:
            return
        menu, action = previous[0](), previous[1]
        try:
            if menu is not None:
                menu.removeAction(action)
            action.triggered.disconnect()
            action.deleteLater()
        except (RuntimeError, TypeError):
            pass

    def _show_check_dialog(self, window, checked=False):
        if self._closing:
            return
        self._ensure_application()
        dialog = WindowModalDialog(window, _("Passphrase Leak Checker"))
        self._checker_dialogs.add(dialog)
        layout = QVBoxLayout(dialog)
        intro = QLabel(_("Check a seed-extension passphrase or wallet password for appearances in leaked data. "
                         "Never enter wallet recovery-seed words."))
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        field = QLineEdit()
        field.setObjectName('passphrase_leak_checker_passphrase')
        field.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow(_("Seed-extension passphrase or wallet password"), field)
        kind = QComboBox()
        kind.setObjectName('passphrase_leak_checker_secret_kind')
        for label, value in (("Wallet password", None), ("Electrum seed extension", 'electrum'),
                             ("BIP39 seed extension", 'bip39'), ("SLIP39 seed extension", 'slip39')):
            kind.addItem(_(label), value)
        form.addRow(_("Value type"), kind)
        layout.addLayout(form)
        button = QPushButton(_("Check for Leaks"))
        button.setObjectName('passphrase_leak_checker_check_leak')
        button.clicked.connect(lambda checked=False: self._on_check_button_clicked(
            field, button, kind_control=kind))
        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(lambda checked=False: dialog.reject())
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(button)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        field.setFocus()
        try:
            self._dialog_exec(dialog)
        finally:
            for thread, context in list(self._check_contexts.items()):
                if context['parent']() is dialog:
                    self._invalidate_check(thread)
            self._checker_dialogs.discard(dialog)
            try:
                field.clear()
                dialog.deleteLater()
            except RuntimeError:
                pass

    @hook
    def password_dialog(self, pw, grid, pos):
        self._ensure_application()
        self._inline_controls.add(pw, grid, pw.window())

    def _cancel_button_check(self, button):
        for thread, context in list(self._check_contexts.items()):
            if context['button']() is button:
                self._invalidate_check(thread)

    def _on_check_button_clicked(self, pw, button, seed_type=None, *, kind_control=None) -> None:
        if self._closing:
            return
        if any(context['button']() is button for context in self._check_contexts.values()):
            return
        if len(self._active_checks) >= self.MAX_ACTIVE_CHECKS:
            QMessageBox.information(pw.window(), _("Passphrase Leak Checker"),
                                    _("Other leak checks are still running. Try again when one finishes."))
            return
        passphrase = pw.text() if hasattr(pw, "text") else ""
        parent = pw.window() if hasattr(pw, "window") else None
        if not passphrase:
            QMessageBox.information(
                parent,
                _("Passphrase Leak Checker"),
                _("Enter a seed-extension passphrase or wallet password first."),
            )
            return

        try:
            field_seed_type = self._inline_controls.seed_type(pw)
            if kind_control is not None:
                seed_type = kind_control.currentData()
            elif seed_type is None:
                seed_type = field_seed_type
            effective, description = prepare_secret(passphrase, seed_type)
            proxy = self._require_network_policy()
            client = self._build_client(proxy=proxy)
            client.secret_description = description
        except LeakCheckError as exc:
            QMessageBox.warning(
                parent,
                _("Passphrase Leak Checker"),
                str(exc),
            )
            return

        if not self._confirm_disclosure(parent, client):
            return

        try:
            if (self._closing or pw.text() != passphrase or not self._inline_controls.is_available(pw)
                    or self._inline_controls.seed_type(pw) != field_seed_type
                    or (kind_control is not None and kind_control.currentData() != seed_type)):
                return
        except RuntimeError:
            return
        self._set_button_busy(button, is_busy=True)
        self._start_async_check(
            parent=parent,
            button=button,
            client=client,
            passphrase=effective,
            source=pw,
            kind_control=kind_control,
        )

    def _require_network_policy(self) -> None:
        try:
            from electrum.network import Network
            network = Network.get_instance()
        except Exception:
            raise LeakCheckError("Cannot verify Electrum's network settings. Leak check unavailable.") from None
        return get_network_proxy(self.config, network)

    def _require_network_route(self, expected):
        if self._require_network_policy() != expected:
            raise LeakCheckError('Electrum connection settings changed. Start a new leak check to approve this connection.')

    def _confirm_disclosure(self, parent, client) -> bool:
        if client.mode == MODE_FULL_HASH:
            disclosure = _(
                "This sends the FULL SHA-1 password hash to the service below. "
                "The password itself stays on this device, but the service can compare guesses against the hash. "
                "Approve only if you trust this service."
            )
        else:
            disclosure = _(
                "This sends only the first five characters of the SHA-1 password hash. "
                "The password and the rest of the hash stay on this device."
            )
        if client.proxy is None:
            route = _("The connection is direct; the service can see your IP address.")
        else:
            route = _("The connection uses Electrum's configured {mode} proxy. "
                      "The proxy resolves the service address. "
                      "Proxy failure will not fall back to a direct connection.").format(mode=client.proxy.mode.upper())
        message = _(
            "This check uses {destination}.\n\n{secret_description}\n\n{disclosure}\n\n"
            "{route} "
            "Any configured HTTP request headers are also sent. Continue?"
        ).format(destination=client.destination, disclosure=disclosure, route=route,
                 secret_description=_(getattr(client, 'secret_description', 'The wallet password is checked exactly as entered.')))
        buttons = QMessageBox.StandardButton
        answer = QMessageBox.question(
            parent, _("Send Leak Check?"), message,
            buttons.Yes | buttons.No, buttons.No,
        )
        if answer != buttons.Yes:
            return False
        if client.mode == MODE_FULL_HASH:
            client.approve_full_hash_disclosure(client.destination)
        return True

    def _start_async_check(self, parent, button, client: PwnedClient, passphrase: str,
                           source=None, kind_control=None, startup=None) -> None:
        if self._closing or len(self._active_checks) >= self.MAX_ACTIVE_CHECKS:
            if not self._closing:
                self._set_button_busy(button, False)
            return
        thread = worker = None
        try:
            thread = QThread()
            worker = _LeakCheckWorker(client=client, passphrase=passphrase)
            context = {'parent': weakref.ref(parent) if parent is not None else lambda: None,
                       'button': weakref.ref(button) if button is not None else lambda: None,
                       'valid': True, 'connections': [], 'startup': startup,
                       'description': getattr(client, 'secret_description', None)}
            self._check_contexts[thread] = context
            for obj, signal_name in ((source, 'textChanged'), (source, 'destroyed'),
                                     (kind_control, 'currentIndexChanged'), (kind_control, 'destroyed'),
                                     (parent, 'finished'), (parent, 'destroyed'), (button, 'destroyed')):
                if obj is None:
                    continue
                signal = getattr(obj, signal_name, None)
                if signal is not None:
                    callback = partial(self._invalidate_check, thread)
                    signal.connect(callback)
                    context['connections'].append((weakref.ref(obj), signal_name, callback))
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.finished.connect(
                partial(self._emit_async_result_to_ui, thread, worker), _DIRECT_CONNECTION
            )
            worker.finished.connect(thread.quit, _DIRECT_CONNECTION)
            worker.finished.connect(worker.deleteLater)
            thread.finished.connect(partial(self._emit_thread_finished, thread, worker), _DIRECT_CONNECTION)
            thread.finished.connect(thread.deleteLater)
            self._active_checks.append((thread, worker))
            thread.start()
        except Exception:
            self._cleanup_failed_start(thread, worker, client)
            self._set_button_busy(button, False)
            parent_widget = self._resolve_parent(button, parent)
            if not self._closing and parent_widget is not None and startup is None:
                QMessageBox.warning(parent_widget, _("Passphrase Leak Checker"),
                                    _("Could not start the leak check. Try again."))

    def _cleanup_failed_start(self, thread, worker, client):
        try:
            client.cancel()
        except Exception:
            pass
        if worker is not None:
            worker._passphrase = None
        if thread is None:
            return
        context = self._check_contexts.get(thread)
        if context is not None:
            context['valid'] = False
        try:
            thread.quit()
            if thread.isRunning():
                # Even an unexpected start exception is not proof of termination.
                return
        except RuntimeError:
            pass
        self._on_thread_finished(thread, worker)
        objects = ((thread, ('started', 'finished')),)
        if worker is not None:
            objects += ((worker, ('finished',)),)
        for obj, signals in objects:
            for name in signals:
                try:
                    getattr(obj, name).disconnect()
                except (RuntimeError, TypeError):
                    pass
            try:
                obj.deleteLater()
            except RuntimeError:
                pass

    def _emit_async_result_to_ui(self, thread, worker, result, error_text) -> None:
        self._ui_invoker.result_ready.emit(thread, worker, result, error_text)

    def _emit_thread_finished(self, thread, worker):
        self._ui_invoker.thread_done.emit(thread, worker)

    def _invalidate_check(self, thread, *args):
        context = self._check_contexts.get(thread)
        if context is not None:
            context['valid'] = False
        for active_thread, worker in self._active_checks:
            if active_thread is thread:
                try:
                    worker.cancel()
                except Exception:
                    pass
                break

    def _on_thread_finished(self, thread, worker):
        self._drop_active_check(thread, worker)
        context = self._check_contexts.pop(thread, None)
        if context is not None:
            for reference, signal_name, callback in context['connections']:
                obj = reference()
                if obj is not None:
                    try:
                        getattr(obj, signal_name).disconnect(callback)
                    except (RuntimeError, TypeError):
                        pass
            if not self._closing and context['button']() is not None:
                self._set_button_busy(context['button'](), False)
        self._release_closed_plugin()

    def _on_async_check_finished(self, parent, button, thread, worker, result, error_text) -> None:
        if self._closing:
            return
        if thread is not None and not any(t is thread and w is worker for t, w in self._active_checks):
            return
        context = self._check_contexts.get(thread)
        if context is not None and not context['valid']:
            return
        startup = context.get('startup') if context is not None else None
        if startup is not None:
            if not self._startup_is_current(parent, startup):
                return
        elif button is None:
            return
        parent_widget = self._resolve_parent(button=button, fallback=parent)
        if parent_widget is None:
            return
        self._set_button_busy(button, is_busy=False)

        outcome = lookup_outcome(result, error_text)
        if startup is not None and outcome != LeakCheckOutcome.MATCH:
            return
        if outcome == LeakCheckOutcome.UNAVAILABLE:
            QMessageBox.warning(
                parent_widget,
                _("Passphrase Leak Checker"),
                str(error_text) if error_text else _("Could not check for leaks. No valid result was received."),
            )
            return

        description = context.get('description') if context is not None else None
        detail = _(description) + '\n\n' if isinstance(description, str) else ''
        if outcome == LeakCheckOutcome.MATCH:
            if result.count_reported:
                appearances = _("Times seen in leaked data: {count}").format(count=f'{result.count:,}')
            else:
                appearances = _("The service did not report how many times it appeared.")
            if startup is not None:
                message = _(
                    "This wallet's seed extension was found in the checked leak data.\n\n"
                    "{appearances}\n\n"
                    "Create a new wallet with a different seed-extension passphrase "
                    "and migrate your funds to it."
                )
            else:
                message = _(
                    "This passphrase or password was found in the checked leak data.\n\n"
                    "{appearances}\n\n"
                    "Choose a different value for new passwords or seed extensions."
                )
            QMessageBox.warning(parent_widget, _("Passphrase Leak Checker"),
                                detail + message.format(appearances=appearances))
            return

        QMessageBox.information(
            parent_widget,
            _("Passphrase Leak Checker"),
            detail + _(
                "Not found in the checked leak data.\n\n"
                "This does not prove that the passphrase or password is strong or safe."
            ),
        )

    def _drop_active_check(self, thread, worker) -> None:
        self._active_checks = [
            (t, w) for (t, w) in self._active_checks if not (t is thread and w is worker)
        ]

    def _set_button_busy(self, button, is_busy: bool) -> None:
        try:
            button.setEnabled(not is_busy)
            button.setText(_("Checking for leaks…") if is_busy else _("Check for Leaks"))
        except Exception:
            return

    @staticmethod
    def _resolve_parent(button, fallback=None):
        for candidate in (button, fallback):
            if candidate is None:
                continue
            try:
                return candidate.window()
            except Exception:
                continue
        return None

    def _show_settings_dialog(self, window) -> None:
        self._ensure_application()
        dialog = WindowModalDialog(window, _("Passphrase Leak Checker Plugin Settings"))
        layout = QVBoxLayout(dialog)

        check_button = EnterButton(_("Check a passphrase or password…"), partial(self._show_check_dialog, dialog))
        check_button.setToolTip(_("Open the checker using your saved service settings."))
        layout.addWidget(check_button)

        intro = QLabel(
            _(
                "The hash is calculated from the passphrase or password on this device. "
                "Choose how much of it to send. Manual checks ask for approval; optional "
                "startup checks use the approval given here. Electrum's proxy and Tor settings apply."
            )
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        endpoint = self._cfg_get(self.CFG_ENDPOINT, self.DEFAULT_ENDPOINT)
        endpoint_edit = QLineEdit(endpoint if isinstance(endpoint, str) else '')
        endpoint_edit.setMinimumWidth(360)
        endpoint_edit.setCursorPosition(0)
        endpoint_edit.setToolTip(_("The leak-check service address, including the required hash placeholders."))
        form.addRow(_("Service URL template"), endpoint_edit)

        mode_combo = QComboBox()
        for mode_value, mode_label in self.MODE_LABELS:
            mode_combo.addItem(_(mode_label), mode_value)
        current_mode = self._cfg_get(self.CFG_MODE, self.DEFAULT_MODE)
        current_index = mode_combo.findData(current_mode)
        mode_combo.setCurrentIndex(current_index if current_index >= 0 else 0)
        form.addRow(_("Hash data sent"), mode_combo)

        timeout_spin = QSpinBox()
        timeout_spin.setRange(1, 60)
        try:
            timeout = PwnedClient._integer_setting(self._cfg_get(self.CFG_TIMEOUT, self.DEFAULT_TIMEOUT_SECONDS))
            if not 1 <= timeout <= 60:
                raise LeakCheckError('Invalid saved timeout.')
        except LeakCheckError:
            timeout = self.DEFAULT_TIMEOUT_SECONDS
            QMessageBox.warning(dialog, _("Passphrase Leak Checker"),
                                _("The saved request time limit is invalid. Choose 1–60 seconds and save settings."))
        timeout_spin.setValue(timeout)
        timeout_spin.setToolTip(_("Maximum time for one request, including connecting and reading the response."))
        form.addRow(_("Request time limit (seconds)"), timeout_spin)

        startup_check = QCheckBox(_("Check seed extension when a wallet opens"))
        startup_check.setObjectName('passphrase_leak_checker_check_extension_on_startup')
        startup_check.setChecked(self._startup_enabled())
        startup_check.setToolTip(_("Off by default. Runs once when a wallet opens, using its stored seed extension. "
                                  "Enabling requires confirmation here. Startup never prompts; locked extensions are skipped. "
                                  "Only leak matches are reported. Silence does not mean a successful check. "
                                  "Recovery-seed words are never read or checked."))
        form.addRow(_("Startup check"), startup_check)

        headers_raw = self._cfg_get(self.CFG_HEADERS_JSON, self.DEFAULT_HEADERS_JSON)
        try:
            safe_headers = json.dumps(self._headers_from_json(headers_raw))
        except LeakCheckError:
            safe_headers = self.DEFAULT_HEADERS_JSON
            QMessageBox.warning(dialog, _("Passphrase Leak Checker"),
                                _("Saved HTTP headers are invalid or unsupported and are hidden. "
                                  "Saving replaces them with the privacy header below; cancelling keeps existing settings. "
                                  "Remove credentials from configuration backups separately."))
        headers_edit = QPlainTextEdit(safe_headers)
        headers_edit.setPlaceholderText('{"Add-Padding":"true"}')
        headers_edit.setMinimumHeight(80)
        headers_edit.setToolTip(_("Only the Add-Padding header set to true is supported. Authentication credentials cannot be stored here."))
        form.addRow(_("Privacy header (JSON)"), headers_edit)

        approved = self._cfg_get(self.CFG_STARTUP_APPROVAL) if self._startup_enabled() else None

        def form_client():
            return PwnedClient(endpoint_template=endpoint_edit.text().strip(), mode=mode_combo.currentData(),
                               timeout_seconds=int(timeout_spin.value()),
                               extra_headers=self._headers_from_json(headers_edit.toPlainText().strip() or '{}'))

        def select_startup(checked):
            nonlocal approved
            approved = None
            if not checked:
                return
            try:
                client = form_client()
                if self._confirm_startup_disclosure(dialog, client):
                    approved = self._startup_approval_for(client)
                    return
            except LeakCheckError as exc:
                QMessageBox.warning(dialog, _("Passphrase Leak Checker"), str(exc))
            startup_check.setChecked(False)

        startup_check.toggled.connect(select_startup)

        layout.addLayout(form)

        tips = QLabel(
            _(
                "Use {prefix} for the first 5 hash characters, {suffix} for the remaining 35, and {hash} for all 40.\n"
                "Have I Been Pwned uses https://api.pwnedpasswords.com/range/{prefix}\n"
                "Use HTTPS. HTTP is allowed only for direct local testing at a loopback IP, without a proxy."
            )
        )
        tips.setWordWrap(True)
        layout.addWidget(tips)

        save_button = OkButton(dialog)
        save_button.setText(_("Save settings"))
        layout.addLayout(Buttons(CancelButton(dialog), save_button))

        while self._dialog_exec(dialog):
            endpoint = endpoint_edit.text().strip()
            mode = mode_combo.currentData()
            timeout_seconds = int(timeout_spin.value())
            headers_raw = headers_edit.toPlainText().strip() or "{}"

            if not endpoint:
                QMessageBox.warning(dialog, _("Passphrase Leak Checker"), _("The service URL cannot be empty."))
                continue

            parsed_headers = self._parse_headers(headers_raw, dialog)
            if parsed_headers is None:
                continue

            try:
                client = PwnedClient(
                    endpoint_template=endpoint,
                    mode=mode,
                    timeout_seconds=timeout_seconds,
                    extra_headers=parsed_headers,
                )
                startup_enabled = startup_check.isChecked()
                if startup_enabled and approved != self._startup_approval_for(client):
                    # Reconfirm disclosure changes before saving the startup option.
                    if self._confirm_startup_disclosure(dialog, client):
                        approved = self._startup_approval_for(client)
                    else:
                        startup_check.setChecked(False)
                        startup_enabled = False
                self._save_settings({
                    self.CFG_ENDPOINT: endpoint,
                    self.CFG_MODE: mode,
                    self.CFG_TIMEOUT: timeout_seconds,
                    self.CFG_HEADERS_JSON: json.dumps(parsed_headers),
                    self.CFG_CHECK_EXTENSION_ON_STARTUP: startup_enabled,
                    self.CFG_STARTUP_APPROVAL: approved if startup_enabled else None,
                })
            except LeakCheckError as exc:
                QMessageBox.warning(dialog, _("Passphrase Leak Checker"), str(exc))
                continue
            return

    def _confirm_startup_disclosure(self, parent, client):
        if client.mode == MODE_FULL_HASH:
            disclosure = _("Each check sends the FULL SHA-1 hash of the seed extension. "
                           "The service can compare password guesses against it.")
        else:
            disclosure = _("Each check sends the first five SHA-1 hash characters of the seed extension. "
                           "Even this prefix reveals information about it.")
        message = _(
            "Enable automatic seed-extension checks for wallets opened with this plugin?\n\n"
            "Startup checks use {destination}.\n\n{disclosure}\n\n"
            "This approval covers future startup checks with these service and sharing settings. "
            "Electrum's proxy and Tor settings apply; direct connections reveal your IP address. "
            "Privacy headers are sent too. The extension itself and recovery-seed words are never sent.\n\n"
            "Startup will not ask questions or unlock a wallet. Locked or unavailable extensions are skipped. "
            "Only confirmed leak matches are reported; no-match results and failed checks stay silent. "
            "Silence does not mean a successful check. Save settings to apply this choice."
        ).format(destination=client.destination, disclosure=disclosure)
        buttons = QMessageBox.StandardButton
        return QMessageBox.question(parent, _("Enable Startup Extension Checks?"), message,
                                    buttons.Yes | buttons.No, buttons.No) == buttons.Yes

    def _save_settings(self, settings):
        # Stage under the host's config lock, then request one complete save.
        # Disk-write atomicity remains the host's responsibility.
        if (self.CFG_CHECK_EXTENSION_ON_STARTUP in settings
                and type(settings[self.CFG_CHECK_EXTENSION_ON_STARTUP]) is not bool):
            raise LeakCheckError('The startup check setting must be enabled or disabled.')
        values = {self._cfg_key(key): value for key, value in settings.items()}
        try:
            with self.config.lock:
                if any(not self.config.is_modifiable(key) for key in values):
                    raise LeakCheckError('Some settings are controlled by Electrum and cannot be changed.')
                previous = {key: self.config.get(key) for key in values}
                try:
                    for key, value in values.items():
                        self.config.set_key(key, value, save=False)
                        if self.config.get(key) != value:
                            raise ValueError('Host refused a settings update.')
                    self.config.save_user_config()
                except Exception:
                    for key, value in previous.items():
                        try:
                            if self.config.get(key) != value:
                                self.config.set_key(key, value, save=False)
                            if self.config.get(key) != value:
                                self._settings_error = True
                        except Exception:
                            self._settings_error = True
                    raise LeakCheckError('Settings could not be saved. Your edits are available for correction or retry.') from None
                self._settings_error = False
            disclosure_keys = (self.CFG_ENDPOINT, self.CFG_MODE, self.CFG_HEADERS_JSON, self.CFG_STARTUP_APPROVAL)
            changed = any(self._cfg_key(key) in previous
                          and previous[self._cfg_key(key)] != settings[key]
                          for key in disclosure_keys if key in settings)
            if settings.get(self.CFG_CHECK_EXTENSION_ON_STARTUP) is False or changed:
                self._startup_checks.clear()
                for thread, context in list(self._check_contexts.items()):
                    if context.get('startup') is not None:
                        self._invalidate_check(thread)
        except LeakCheckError:
            raise
        except Exception:
            raise LeakCheckError('Cannot access Electrum settings. Your edits have been kept in this dialog.') from None

    def _build_client(self, proxy=None) -> PwnedClient:
        if self._settings_error:
            raise LeakCheckError('Settings recovery failed. Save valid settings before checking a passphrase.')
        endpoint = self._cfg_get(self.CFG_ENDPOINT, self.DEFAULT_ENDPOINT)
        mode = self._cfg_get(self.CFG_MODE, self.DEFAULT_MODE)
        timeout_seconds = self._cfg_get(self.CFG_TIMEOUT, self.DEFAULT_TIMEOUT_SECONDS)
        headers_json = self._cfg_get(self.CFG_HEADERS_JSON, self.DEFAULT_HEADERS_JSON)
        headers = self._headers_from_json(headers_json)
        return PwnedClient(
            endpoint_template=endpoint,
            mode=mode,
            timeout_seconds=timeout_seconds,
            extra_headers=headers,
            network_guard=partial(self._require_network_route, proxy),
            proxy=proxy,
            transport=ElectrumHttpTransport(proxy),
        )

    def _parse_headers(self, raw_headers: str, parent) -> Dict[str, str] | None:
        try:
            return self._headers_from_json(raw_headers)
        except LeakCheckError as exc:
            QMessageBox.warning(parent, _("Passphrase Leak Checker"), str(exc))
            return None

    def _headers_from_json(self, raw_headers: str) -> Dict[str, str]:
        try:
            parsed = PwnedClient._load_json(raw_headers)
        except (LeakCheckError, TypeError):
            raise LeakCheckError("HTTP request headers must be valid JSON; correct them in settings.") from None
        headers = PwnedClient._sanitize_headers(parsed)
        if any(key.lower() != 'add-padding' or value != 'true' for key, value in headers.items()):
            raise LeakCheckError('Only the Add-Padding header set to true can be saved. Remove authentication or custom headers from settings.')
        return headers

    def _cfg_key(self, key: str) -> str:
        return f"{self.name}.{key}"

    def _cfg_get(self, key: str, default=None):
        return self.config.get(self._cfg_key(key), default)

    @staticmethod
    def _dialog_exec(dialog) -> bool:
        if hasattr(dialog, "exec"):
            return bool(dialog.exec())
        return bool(dialog.exec_())
