"""Check client lookups against local synthetic breach data."""

from http.server import HTTPServer
import threading
import unittest

from passphrase_leak_checker.client import (
    LeakCheckError, MODE_FULL_HASH, MODE_K_ANONYMITY, PwnedClient,
)
from tests.fixtures.mock_backend import MockPwnedHandler, PUBLIC_SEED_EXAMPLE


# Public test values only. Counts describe the synthetic dataset.
EXAMPLE_LOOKUPS = (
    ("weak password", "password", 26230667),
    ("numeric weak password", "123456", 180041686),
    ("dictionary weak password", "letmein", 3938635),
    ("famous long passphrase", "correct horse battery staple", 512),
    ("guessable password absent from fixture", "aaaaaaa", 0),
    ("random-looking public example", "D7!qL2@vN9#sR4$xT6%wK8", 0),
    ("published Electrum seed", PUBLIC_SEED_EXAMPLE, 1),
    ("Unicode passphrase text", "café 🔑", 0),
)


class MockFlowTests(unittest.TestCase):
    def test_public_examples_across_lookup_modes(self):
        with HTTPServer(('127.0.0.1', 0), MockPwnedHandler) as server:
            thread = threading.Thread(
                target=lambda: server.serve_forever(poll_interval=0.01), daemon=True,
            )
            thread.start()
            try:
                base_url = f'http://127.0.0.1:{server.server_port}'
                for mode, path in (
                    (MODE_K_ANONYMITY, "/range/{prefix}"),
                    (MODE_FULL_HASH, "/hash/{hash}"),
                    (MODE_FULL_HASH, "/query?prefix={prefix}&suffix={suffix}"),
                ):
                    with self.subTest(mode=mode, route=path):
                        client = PwnedClient(
                            endpoint_template=base_url + path,
                            mode=mode,
                            timeout_seconds=3,
                            extra_headers={"Add-Padding": "true"},
                            full_hash_consent=(mode == MODE_FULL_HASH),  # Public fixtures only.
                        )
                        for label, secret, count in EXAMPLE_LOOKUPS:
                            with self.subTest(example=label):
                                result = client.check_secret(secret)
                                self.assertEqual(result.count, count)
                                self.assertEqual(result.is_pwned, count > 0)

                for settings in (
                    {"endpoint_template": "file:///tmp/anything/{prefix}"},
                    {"endpoint_template": "http://example.com/range/{prefix}"},
                    {"endpoint_template": base_url + "/range/{prefix}",
                     "extra_headers": {"X-Test": "ok\r\nInjected: bad"}},
                ):
                    with self.subTest(settings=settings), self.assertRaises(LeakCheckError):
                        PwnedClient(**settings)

                client = PwnedClient(
                    endpoint_template=base_url + "/redirect/{prefix}",
                    mode=MODE_K_ANONYMITY,
                    timeout_seconds=3,
                )
                with self.subTest(response='redirect'), self.assertRaises(LeakCheckError):
                    client.check_secret("password")
            finally:
                server.shutdown()
                thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
