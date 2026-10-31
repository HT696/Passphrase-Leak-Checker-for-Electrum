"""The offline command must stop accidental networking before any request."""

import contextlib
import io
import socket
import sys
import unittest
from unittest.mock import patch

from scripts.test import build_suite, forbid_network, main


class TestRunnerTests(unittest.TestCase):
    def test_offline_guard_refuses_dns_connections_and_server_binding(self):
        with forbid_network():
            operations = (
                lambda: socket.getaddrinfo('example.invalid', 443),
                lambda: socket.gethostbyname('example.invalid'),
                lambda: socket.gethostbyname_ex('example.invalid'),
                lambda: socket.gethostbyaddr('127.0.0.1'),
                lambda: socket.getnameinfo(('127.0.0.1', 1), 0),
                lambda: socket.create_connection(('127.0.0.1', 1)),
                lambda: socket.socket.connect(None, ('127.0.0.1', 1)),
                lambda: socket.socket.connect_ex(None, ('127.0.0.1', 1)),
                lambda: socket.socket.bind(None, ('127.0.0.1', 0)),
                lambda: socket.socket.sendto(None, b'public test', ('127.0.0.1', 1)),
                lambda: socket.socket.send(None, b'public test'),
                lambda: socket.socket.sendall(None, b'public test'),
            )
            for operation in operations:
                with self.subTest(operation=operation), self.assertRaisesRegex(AssertionError, 'forbidden'):
                    operation()

    def test_guard_restores_functions_after_an_exception(self):
        original = socket.getaddrinfo
        with self.assertRaises(ValueError):
            with forbid_network():
                raise ValueError('public test')
        self.assertIs(socket.getaddrinfo, original)

    def test_offline_selection_excludes_real_http_and_subprocess_tests(self):
        def ids(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    yield from ids(item)
                else:
                    yield item.id()
        tests = list(ids(build_suite('offline')))
        self.assertTrue(any('test_transport_contract' in name for name in tests))
        self.assertTrue(any('test_electrum_lifecycle' in name for name in tests))
        for excluded in ('tests.integration.test_http.', 'tests.integration.test_mock_flow.',
                         'tests.integration.test_socks_transport.',
                         'tests.integration.test_deadline.', 'tests.integration.test_packaging.'):
            self.assertFalse(any(name.startswith(excluded) for name in tests), excluded)

    def test_skipped_tests_fail_the_release_command(self):
        def skipped():
            raise unittest.SkipTest('public missing dependency example')
        suite = unittest.TestSuite([unittest.FunctionTestCase(skipped)])
        with patch.object(sys, 'argv', ['test.py', '--suite', 'unit', '--fail-on-skip']), \
                patch('scripts.test.build_suite', return_value=suite), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 1)

    def test_unknown_suite_is_not_silently_treated_as_all(self):
        with self.assertRaises(ValueError):
            build_suite('typo')

    def test_expected_failures_cannot_make_release_validation_green(self):
        class KnownFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_blocker(self):
                self.fail('public example of a release blocker')
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(KnownFailure)
        with patch.object(sys, 'argv', ['test.py', '--suite', 'unit', '--strict']), \
                patch('scripts.test.build_suite', return_value=suite), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 1)

    def test_empty_suite_is_not_a_success(self):
        with patch.object(sys, 'argv', ['test.py', '--suite', 'unit']), \
                patch('scripts.test.build_suite', return_value=unittest.TestSuite()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(), 1)
