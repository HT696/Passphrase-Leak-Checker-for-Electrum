"""Apply host seed rules without copying normalization or mnemonic validators."""

from .pwned_api import LeakCheckError

NATIVE_SEED_TYPES = frozenset(('standard', 'segwit', '2fa', '2fa_segwit'))
SECRET_LABELS = {
    'password': 'The wallet password is checked exactly as entered.',
    'electrum': 'The Electrum seed extension is checked as Electrum-normalized text.',
    'bip39': 'The BIP39 seed extension is checked as NFKD-normalized text.',
    'slip39': 'The SLIP39 seed extension is checked exactly as entered.',
}


def prepare_secret(text, seed_type=None):
    """None denotes a password; unknown extension formats must never reach here."""
    try:
        refuse_mnemonic(text)
        if seed_type is None:
            value, kind = text, 'password'
        elif seed_type in NATIVE_SEED_TYPES or seed_type == 'electrum':
            from electrum.mnemonic import normalize_text
            value, kind = normalize_text(text), 'electrum'
        elif seed_type == 'bip39':
            from electrum.keystore import bip39_normalize_passphrase
            value, kind = bip39_normalize_passphrase(text), 'bip39'
        elif seed_type == 'slip39':
            # Electrum's EncryptedSeed.decrypt uses the extension's UTF-8 bytes.
            value, kind = text, 'slip39'
        else:
            raise LeakCheckError('Cannot determine the seed format. Use the manual checker and select its format.')
        if not isinstance(value, str) or not value:
            raise LeakCheckError('The effective password or seed extension is empty.')
        return value, SECRET_LABELS[kind]
    except LeakCheckError:
        raise
    except Exception:
        raise LeakCheckError('Cannot apply Electrum seed rules. Leak check unavailable.') from None


def refuse_mnemonic(text):
    """Conservatively recognize supported recovery phrases, entirely locally.

    This is a paste guard, not a guarantee that arbitrary recovery material can
    be identified. No mnemonic widget or wallet seed is read.
    """
    words = text.split()
    # Electrum's version test also accepts occasional arbitrary short strings;
    # only apply it to plausible recovery phrases or hexadecimal recovery seeds.
    hex_seed = len(text) in (32, 64) and all(c in '0123456789abcdefABCDEF' for c in text)
    if len(words) < 12 and not hex_seed:
        return
    from electrum.mnemonic import is_seed
    from electrum.keystore import bip39_is_checksum_valid

    recognized = is_seed(text)
    if len(words) in (12, 15, 18, 21, 24):
        recognized = recognized or bip39_is_checksum_valid(text) == (True, True)
    if not recognized and len(words) in (20, 33):
        from electrum.slip39 import decode_mnemonic, Slip39Error
        try:
            decode_mnemonic(text)
        except Slip39Error:
            pass
        else:
            recognized = True
    if recognized:
        raise LeakCheckError('This looks like wallet recovery-seed material. It will not be sent for a leak check.')
