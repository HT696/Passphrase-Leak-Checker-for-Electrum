#!/usr/bin/env python3
"""Check real host routing, seed rules and session factories without requests.

Does not install dependencies, start Electrum networking, or open a wallet.
GUI integration, plugin discovery and independent security review need separate checks.
"""

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import asyncio
import ssl

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]


def check_host_helpers():
    from electrum.mnemonic import normalize_text
    from electrum.keystore import bip39_normalize_passphrase
    from electrum.util import make_aiohttp_session, get_asyncio_loop
    from electrum.network import ProxySettings
    from passphrase_leak_checker.electrum.secret_policy import prepare_secret
    from tests.support.electrum_http import check_http_adapter, check_http_isolation, check_upstream_http_behavior
    from passphrase_leak_checker import LeakCheckError

    assert callable(get_asyncio_loop)
    for raw, effective in (('  PASSWORD  ', 'password'), ('CAFÉ', 'cafe')):
        assert normalize_text(raw) == effective
        assert prepare_secret(raw, 'segwit')[0] == effective
    raw = '  CAFÉ  '
    assert bip39_normalize_passphrase(raw) == '  CAFE\u0301  '
    assert prepare_secret(raw, 'bip39')[0] == bip39_normalize_passphrase(raw)
    for kind in (None, 'slip39'):
        assert prepare_secret(raw, kind)[0] == raw
    # Public BIP39 test vector, never material from a wallet or local example.
    try:
        prepare_secret(' '.join(['abandon'] * 11 + ['about']))
    except LeakCheckError as exc:
        assert 'recovery-seed' in str(exc)
    else:
        raise AssertionError('Public BIP39 mnemonic was not refused')
    print('PASS: real host normalization and mnemonic guard')

    async def sessions():
        for mode in (None, 'socks5', 'socks4'):
            proxy = None if mode is None else ProxySettings.from_dict({
                'enabled': True, 'mode': mode, 'host': '127.0.0.1', 'port': '9050'})
            async with make_aiohttp_session(proxy, headers={'Add-Padding': 'true'}, timeout=3) as session:
                assert not session.trust_env
                assert session.timeout.total == 3
                # Verify the real factory's configured TLS context, without I/O.
                context = session.connector._ssl
                assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
                if mode is not None:
                    assert session.connector.__class__.__name__ == 'ProxyConnector'
        await check_http_adapter()
        await check_http_isolation()
        await check_upstream_http_behavior()
    asyncio.run(sessions())
    print('PASS: real host direct and SOCKS session factories and verified TLS defaults (no requests)')


def main() -> int:
    try:
        import aiohttp
        import aiohttp_socks
        from electrum.version import ELECTRUM_VERSION
        from electrum.simple_config import SimpleConfig
        from electrum.network import Network, ProxySettings
    except (ImportError, OSError) as exc:
        print(f"Electrum or a required dependency is unavailable: {exc}", file=sys.stderr)
        print("Provide the Electrum 4.8.3 source tree and its packages directory on PYTHONPATH; "
              "this command downloads nothing.", file=sys.stderr)
        return 2
    if ELECTRUM_VERSION != "4.8.3":
        print(f"Expected Electrum 4.8.3, found {ELECTRUM_VERSION}. No checks run.", file=sys.stderr)
        return 2
    print(f'Host: Electrum {ELECTRUM_VERSION}; aiohttp {aiohttp.__version__}; '
          f'aiohttp-socks {aiohttp_socks.__version__}')

    from passphrase_leak_checker.electrum.network_policy import get_network_proxy
    from passphrase_leak_checker import LeakCheckError, PwnedClient, SocksProxy

    cases = (
        ("direct", False, None, False, False),
        ("offline", True, None, False, True),
        ("SOCKS5 or Tor", False, "socks5:127.0.0.1:9050", True, False),
        ("SOCKS4", False, "socks4:127.0.0.1:9050", True, False),
    )
    with tempfile.TemporaryDirectory(prefix="passphrase_leak_checker-host-") as directory:
        for name, offline, proxy, enabled, expect_refusal in cases:
            config = SimpleConfig({"electrum_path": str(Path(directory) / name.replace('/', '-')),
                                   "offline": offline, "proxy": proxy, "enable_proxy": enabled})
            # Exercise real host accessors without starting its network event loop.
            state = SimpleNamespace(default_server=None, proxy=ProxySettings.from_config(config),
                                    auto_connect=True, oneserver=False)
            network = SimpleNamespace(get_parameters=lambda: Network.get_parameters(state))
            with patch("socket.getaddrinfo", side_effect=AssertionError("Unexpected DNS")) as dns, \
                    patch("socket.socket.connect", side_effect=AssertionError("Unexpected connection")) as connect:
                try:
                    route = get_network_proxy(config, network)
                except LeakCheckError:
                    if not expect_refusal:
                        raise
                else:
                    if expect_refusal:
                        raise AssertionError(f"{name}: privacy policy allowed a forbidden route")
                    if enabled:
                        expected = SocksProxy('127.0.0.1', 9050, mode='socks5' if name == 'SOCKS5 or Tor' else 'socks4')
                        if route != expected:
                            raise AssertionError(f'{name}: wrong proxy route snapshot')
                    elif route is not None:
                        raise AssertionError(f'{name}: unexpected proxy route')
                if expect_refusal:
                    client = PwnedClient("https://example.invalid/{prefix}",
                                         network_guard=lambda: get_network_proxy(config, network))
                    try:
                        client.check_secret("synthetic host validation")
                    except LeakCheckError:
                        pass
                    else:
                        raise AssertionError(f"{name}: lookup unexpectedly succeeded")
                dns.assert_not_called()
                connect.assert_not_called()
            print(f"PASS: {name}")
    check_host_helpers()
    print("Host API checks passed. Real requests, GUI installation and wallet workflows remain separate.")
    return 0


if __name__ == "__main__":
    # Install the guard before host imports, not merely around individual cases.
    from scripts.test import forbid_network
    with forbid_network():
        raise SystemExit(main())
