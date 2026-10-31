"""Public errors must not disclose request data through chained tracebacks."""

import io
import traceback
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from passphrase_leak_checker.client import LeakCheckError, MODE_FULL_HASH, PwnedClient
from tests.support import HASH


PRIVATE_DIAGNOSTIC = 'public-sentinel-authorization-value'


class DiagnosticPrivacyTests(unittest.TestCase):
    def assert_redacted(self, operation):
        try:
            operation()
        except LeakCheckError as error:
            diagnostic = ''.join(traceback.format_exception(type(error), error, error.__traceback__))
        else:
            self.fail('Expected a handled lookup failure.')
        self.assertNotIn(HASH, diagnostic)
        self.assertNotIn(PRIVATE_DIAGNOSTIC, diagnostic)

    def test_transport_error_tracebacks_do_not_include_hash_urls_or_credentials(self):
        errors = (
            HTTPError('https://example.invalid/' + HASH, 403, PRIVATE_DIAGNOSTIC, None, io.BytesIO()),
            URLError(HASH + PRIVATE_DIAGNOSTIC),
            OSError(HASH + PRIVATE_DIAGNOSTIC),
            TimeoutError(HASH + PRIVATE_DIAGNOSTIC),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                client = PwnedClient('https://example.invalid/{hash}', MODE_FULL_HASH, full_hash_consent=True)
                opener = Mock()
                opener.open.side_effect = error
                with patch('passphrase_leak_checker.client.build_opener', return_value=opener):
                    self.assert_redacted(lambda: client.check_secret('password'))
                opener.open.assert_called_once()

    def test_unexpected_policy_error_tracebacks_do_not_include_private_diagnostics(self):
        guard = Mock(side_effect=RuntimeError(PRIVATE_DIAGNOSTIC))
        client = PwnedClient('https://example.invalid/{prefix}', network_guard=guard)
        with patch('passphrase_leak_checker.client.build_opener') as opener:
            self.assert_redacted(lambda: client.check_secret('password'))
        opener.return_value.open.assert_not_called()

    def test_invalid_port_errors_do_not_echo_the_configured_value(self):
        self.assert_redacted(lambda: PwnedClient('https://example.invalid:' + PRIVATE_DIAGNOSTIC + '/{prefix}'))
