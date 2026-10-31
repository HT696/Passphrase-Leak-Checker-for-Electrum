#!/usr/bin/env python3
"""Run repository tests without installing packages or downloading dependencies."""

import argparse
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]


@contextmanager
def forbid_network():
    """Fail before DNS, binding a server, or connecting, including loopback."""
    def refused(*args, **kwargs):
        raise AssertionError("Network access is forbidden in the offline test suite.")

    with ExitStack() as stack:
        for name in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'gethostbyaddr',
                     'getnameinfo', 'create_connection'):
            stack.enter_context(patch.object(socket, name, refused))
        for name in ('connect', 'connect_ex', 'bind', 'send', 'sendall', 'sendto'):
            stack.enter_context(patch.object(socket.socket, name, refused))
        yield


def build_suite(name: str) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    if name == 'offline':
        return unittest.TestSuite((
            loader.discover(str(ROOT / 'tests/unit'), top_level_dir=str(ROOT)),
            loader.loadTestsFromName('tests.integration.test_electrum_qt'),
            loader.loadTestsFromName('tests.integration.test_checker_ui'),
            loader.loadTestsFromName('tests.integration.test_qt_threads'),
            loader.loadTestsFromName('tests.integration.test_qt_startup'),
            loader.discover(str(ROOT / 'tests/readiness'), top_level_dir=str(ROOT)),
        ))
    if name not in {'all', 'unit', 'integration', 'readiness'}:
        raise ValueError('Unknown test suite.')
    start = ROOT / 'tests'
    if name != 'all':
        start /= name
    return loader.discover(str(start), top_level_dir=str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", "unit", "integration", "offline", "readiness"), default="all")
    parser.add_argument('--no-network', action='store_true', help='Block DNS and socket operations in this process.')
    parser.add_argument('--strict', '--fail-on-skip', dest='strict', action='store_true',
                        help='Fail on skipped or expected-failure tests as well as ordinary failures.')
    args = parser.parse_args()
    context = forbid_network() if args.no_network or args.suite == 'offline' else nullcontext()
    with context:
        suite = build_suite(args.suite)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    if args.strict and (result.skipped or result.expectedFailures):
        print('Required tests were skipped or marked as expected failures; validation is incomplete.', file=sys.stderr)
        return 1
    return 0 if result.testsRun and result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
