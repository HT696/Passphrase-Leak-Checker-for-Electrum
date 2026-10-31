"""Small adversarial inputs through the actual HTTP parser; no sockets or DNS."""

from http.client import HTTPException
import io
from threading import Event
import unittest
from unittest.mock import patch

from passphrase_leak_checker.client import (
    LeakCheckError, MAX_HTTP_METADATA_BYTES, PwnedClient, _BudgetReader, _RequestBudget,
)
from tests.support import HASH
from tests.unit.test_request_budget import MemorySocket, Wire


class CountedWire(Wire):
    def __init__(self, data, clock, **kwargs):
        super().__init__(data, clock, **kwargs)
        self.consumed = 0
        self.requests = []

    def read1(self, size=-1):
        self.requests.append(size)
        data = super().read1(size)
        self.consumed += len(data)
        return data


class FramingSecurityTests(unittest.TestCase):
    prefix = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n'

    def lookup(self, framing, *, limit=128, clock=None, step=0):
        clock = [0.0] if clock is None else clock
        self.wire = CountedWire(self.prefix + framing, clock, step=step, body_only=True)
        self.sock = MemorySocket(self.wire)
        with patch('passphrase_leak_checker.client.socket.socket', return_value=self.sock), \
                patch('passphrase_leak_checker.client.time.monotonic', side_effect=lambda: clock[0]):
            return PwnedClient('http://127.0.0.1/{prefix}', max_response_bytes=limit,
                               timeout_seconds=1).check_secret('password')

    def test_negative_and_invalid_chunks_are_rejected_before_their_payload_is_read(self):
        for size in (b'-1', b'-F', b'+1', b'0x10', b' 1', b'1 ', b'1\n', b'G', b''):
            with self.subTest(size=size), self.assertRaises(LeakCheckError):
                self.lookup(size + b'\r\n' + b'x' * 8192, limit=16)
            self.assertLessEqual(self.wire.consumed, len(self.prefix) + len(size) + 2)
            self.assertTrue(all(size >= 0 for size in self.wire.requests))
            self.assertTrue(self.sock.closed)

    def test_incomplete_and_trailer_framing_never_produces_a_result(self):
        for framing in (b'0\r\n', b'0\r\n\r', b'1\r\nx', b'1\r\nxXX0\r\n\r\n', b'2\r\nx\r\n0\r\n\r\n',
                        b'0\r\nX-Trailer: ' + b'x' * 8192 + b'\r\n\r\n'):
            with self.subTest(length=len(framing)), self.assertRaises(LeakCheckError):
                self.lookup(framing)
            self.assertTrue(self.sock.closed)
        # A long trailer is rejected after the first three bytes.
        self.assertLess(self.wire.consumed, len(self.prefix) + 10)

    def test_huge_chunk_is_bounded_before_allocation(self):
        with self.assertRaises(LeakCheckError):
            self.lookup(b'FFFFFFFFFFFFFFFF\r\n' + b'x' * 8192, limit=16)
        self.assertLess(self.wire.consumed, len(self.prefix) + 64)

    def test_excessive_chunk_extensions_have_a_wire_budget(self):
        body = (b'1;' + b'x' * 4000 + b'\r\na\r\n') * 40 + b'0\r\n\r\n'
        with self.assertRaises(LeakCheckError):
            self.lookup(body, limit=128)
        self.assertLessEqual(self.wire.consumed, 128 + MAX_HTTP_METADATA_BYTES)

    def test_slow_chunk_metadata_cannot_restart_the_deadline(self):
        clock = [0.0]
        with self.assertRaises(LeakCheckError):
            self.lookup(b'1;' + b'x' * 100 + b'\r\nx\r\n0\r\n\r\n', clock=clock, step=0.1)
        self.assertLess(clock[0], 1.11)

    def test_cancellation_during_chunk_size_closes_the_connection(self):
        client = PwnedClient('http://127.0.0.1/{prefix}')
        wire = CountedWire(self.prefix + b'1\r\nx\r\n0\r\n\r\n', [0.0])
        sock = MemorySocket(wire)
        original = wire.read1
        def cancel_read(size):
            if wire.tell() >= len(self.prefix):
                client.cancel()
            return original(size)
        wire.read1 = cancel_read
        with patch('passphrase_leak_checker.client.socket.socket', return_value=sock), self.assertRaises(LeakCheckError):
            client.check_secret('password')
        self.assertTrue(sock.closed)

    def test_unbounded_reads_are_rejected_without_reading_underlying_stream(self):
        stream = io.BytesIO(b'public synthetic bytes')
        reader = _BudgetReader(stream, MemorySocket(stream), _RequestBudget(1, Event()))
        for read in (reader.read, reader.read1, reader.readline):
            with self.assertRaises(HTTPException):
                read(-1)
        self.assertEqual(stream.tell(), 0)

    def test_huge_json_integers_and_constants_are_rejected_before_conversion(self):
        for body in ('9' * 8192, '{"count":' + '9' * 8192 + '}', 'NaN', 'Infinity', '-Infinity'):
            with self.subTest(length=len(body)), self.assertRaises(LeakCheckError):
                PwnedClient._parse_full_hash_response(body, HASH)
