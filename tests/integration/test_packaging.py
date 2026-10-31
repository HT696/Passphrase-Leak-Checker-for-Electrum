"""Validate core imports and the self-contained plugin artifact."""

import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from scripts.build_electrum import ROOT, build


class PackagingTests(unittest.TestCase):
    def test_core_import_does_not_load_a_host(self):
        code = """
import sys
sys.path.insert(0, sys.argv[1])
from passphrase_leak_checker import PwnedClient, SocksProxy
assert PwnedClient('https://example.com/{prefix}').mode == 'k_anonymity'
assert PwnedClient('https://example.com/{prefix}', proxy=SocksProxy('127.0.0.1', 9050)).proxy.port == 9050
assert not any(name.startswith(('electrum', 'PyQt', 'passphrase_leak_checker.electrum'))
               for name in sys.modules)
"""
        subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT / "src")],
                       check=True, capture_output=True, text=True, timeout=10)

    def test_plugin_is_reproducible_and_self_contained(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            first = build(directory / "first")
            second = build(directory / "second")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            provenance = json.loads(first.with_suffix('.provenance.json').read_text())
            self.assertEqual(provenance, json.loads(second.with_suffix('.provenance.json').read_text()))
            digest = hashlib.sha256(first.read_bytes()).hexdigest()
            self.assertEqual(first.with_suffix('.zip.sha256').read_text(), f'{digest}  {first.name}\n')
            self.assertEqual(provenance['artifact'], {'name': first.name, 'sha256': digest})
            with zipfile.ZipFile(first) as archive:
                prefix = "electrum_passphrase_leak_checker/"
                manifest = json.loads(archive.read(prefix + "manifest.json"))
                self.assertEqual(manifest["name"], "electrum_passphrase_leak_checker")
                self.assertEqual(manifest["fullname"], "Passphrase Leak Checker")
                self.assertEqual(manifest["author"], "HT696")
                self.assertEqual(manifest["description"],
                                 "Checks seed-extension passphrases and wallet passwords against known leaked data")
                self.assertEqual(manifest['min_electrum_version'], '4.8.3')
                self.assertEqual(manifest['max_electrum_version'], '4.8.3')
                self.assertEqual(archive.read(prefix + "pwned_api.py"),
                                 (ROOT / "src/passphrase_leak_checker/client.py").read_bytes())
                self.assertFalse(any("__pycache__" in name or name.endswith(".pyc")
                                     for name in archive.namelist()))
                allowed = {'__init__.py', 'qt.py', 'inline_controls.py', 'network_policy.py', 'http_transport.py', 'secret_policy.py', 'manifest.json',
                           'pwned_api.py', 'LICENSE'}
                self.assertEqual(set(archive.namelist()), {prefix + name for name in allowed})
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))
                self.assertEqual(set(provenance['inputs']), allowed)
                self.assertEqual(archive.read(prefix + 'LICENSE'), (ROOT / 'LICENSE').read_bytes())
                for name, source in provenance['inputs'].items():
                    self.assertEqual(source['sha256'], hashlib.sha256(archive.read(prefix + name)).hexdigest())
                for info in archive.infolist():
                    self.assertEqual(info.date_time, (2020, 1, 1, 0, 0, 0))
                    self.assertEqual(info.external_attr >> 16, 0o100644)
                    self.assertFalse(info.filename.startswith('/'))
                    self.assertNotIn('..', info.filename.split('/'))
                for name in ('__init__.py', 'qt.py', 'inline_controls.py', 'network_policy.py', 'http_transport.py', 'secret_policy.py', 'manifest.json'):
                    self.assertEqual(archive.read(prefix + name),
                                     (ROOT / 'src/passphrase_leak_checker/electrum' / name).read_bytes())
            code = """
import sys
sys.path.insert(0, sys.argv[1])
import electrum_passphrase_leak_checker as plugin
from electrum_passphrase_leak_checker.pwned_api import PwnedClient, SocksProxy
from electrum_passphrase_leak_checker.network_policy import get_network_proxy
client = PwnedClient('https://example.com/{prefix}')
assert PwnedClient('https://example.com/{prefix}', proxy=SocksProxy('127.0.0.1', 9050)).proxy.port == 9050
assert client._parse_k_anonymity_response('A' * 35 + ':2', 'A' * 35) == 2
assert 'passphrase_leak_checker' not in sys.modules
assert plugin.description == sys.argv[2]
"""
            subprocess.run([sys.executable, "-I", "-B", "-c", code, str(first), manifest["description"]],
                           cwd=directory, check=True, capture_output=True, text=True, timeout=10)

    def test_identity_and_version_mismatch_fail_before_writing_artifacts(self):
        path = ROOT / 'src/passphrase_leak_checker/electrum/manifest.json'
        original = json.loads(path.read_text())
        for key, value in (('version', '999.0.0'), ('name', 'different_plugin')):
            with self.subTest(field=key), tempfile.TemporaryDirectory() as directory:
                manifest = dict(original, **{key: value})
                output = Path(directory) / 'artifact'
                with patch('scripts.build_electrum.json.loads', return_value=manifest), self.assertRaises(ValueError):
                    build(output)
                self.assertFalse(output.exists())
