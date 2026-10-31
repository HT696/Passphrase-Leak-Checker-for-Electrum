try:
    from electrum.i18n import _
except Exception:
    def _(text):
        return text

fullname = _("Passphrase Leak Checker")
description = _(
    "Checks seed-extension passphrases and wallet passwords against known leaked data"
)
available_for = ["qt"]
