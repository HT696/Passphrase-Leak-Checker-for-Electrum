#!/usr/bin/env python3
"""Tiny local mock backend for passphrase leak checks."""

import argparse
import hashlib
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable
from urllib.parse import parse_qs, urlparse

HEX_5_RE = re.compile(r"^[A-F0-9]{5}$")
HEX_40_RE = re.compile(r"^[A-F0-9]{40}$")


def sha1_hex(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest().upper()


# Published at https://electrum.readthedocs.io/en/latest/faq.html#what-is-the-seed
# Public test data only; never use it to hold funds. Its count below is synthetic.
PUBLIC_SEED_EXAMPLE = (
    "slim sugar lizard predict state cute awkward asset inform blood civil sugar"
)


DEFAULT_LEAKED_PASSPHRASES = {
    "password": 26230667,
    "123456": 180041686,
    "letmein": 3938635,
    "correct horse battery staple": 512,
    PUBLIC_SEED_EXAMPLE: 1,
}

LEAKED_HASHES = {
    sha1_hex(passphrase): count for passphrase, count in DEFAULT_LEAKED_PASSPHRASES.items()
}


class MockPwnedHandler(BaseHTTPRequestHandler):
    server_version = "MockPwnedBackend/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/healthz":
            self._send_text(200, "ok\n")
            return

        if path.startswith("/range/"):
            self._handle_range_lookup(path)
            return

        if path.startswith("/hash/"):
            self._handle_full_hash_lookup(path)
            return

        if path.startswith("/redirect/"):
            self._handle_redirect(path)
            return

        if path == "/query":
            self._handle_query_lookup(parsed.query)
            return

        self._send_json(404, {"error": "Unknown endpoint"})

    def _handle_range_lookup(self, path: str) -> None:
        prefix = path[len("/range/") :].strip().upper()
        if not HEX_5_RE.fullmatch(prefix):
            self._send_json(400, {"error": "Prefix must be exactly 5 hex characters"})
            return

        lines = []
        for full_hash, count in LEAKED_HASHES.items():
            if full_hash.startswith(prefix):
                lines.append(f"{full_hash[5:]}:{count}")

        if not lines or self.headers.get("Add-Padding", "").strip().lower() == "true":
            lines.extend(self._padding_lines(prefix, existing=lines))

        body = ""
        if lines:
            body = "\r\n".join(lines) + "\r\n"
        self._send_text(200, body)

    def _handle_full_hash_lookup(self, path: str) -> None:
        full_hash = path[len("/hash/") :].strip().upper()
        if not HEX_40_RE.fullmatch(full_hash):
            self._send_json(400, {"error": "Hash must be exactly 40 hex characters"})
            return

        count = LEAKED_HASHES.get(full_hash, 0)
        self._send_json(
            200,
            {
                "found": count > 0,
                "count": count,
                "hash": full_hash,
            },
        )

    def _handle_query_lookup(self, query_string: str) -> None:
        query = parse_qs(query_string, keep_blank_values=True)
        full_hash = first_or_empty(query.get("hash")).upper()
        prefix = first_or_empty(query.get("prefix")).upper()
        suffix = first_or_empty(query.get("suffix")).upper()

        if not full_hash and prefix and suffix:
            full_hash = f"{prefix}{suffix}"

        if not HEX_40_RE.fullmatch(full_hash):
            self._send_json(
                400,
                {"error": "Expected valid 40-char hex hash or valid prefix+suffix params"},
            )
            return

        count = LEAKED_HASHES.get(full_hash, 0)
        self._send_json(200, {"found": count > 0, "count": count})

    def _handle_redirect(self, path: str) -> None:
        prefix = path[len("/redirect/") :].strip().upper()
        if not HEX_5_RE.fullmatch(prefix):
            self._send_json(400, {"error": "Prefix must be exactly 5 hex characters"})
            return
        self.send_response(302)
        self.send_header("Location", f"/range/{prefix}")
        self.end_headers()

    def _padding_lines(self, prefix: str, existing: Iterable[str]) -> Iterable[str]:
        existing_suffixes = {line.split(":", 1)[0].upper() for line in existing if ":" in line}
        padding = []
        # Deterministic fake rows so callers can test Add-Padding handling.
        for idx in range(1, 6):
            fake_full_hash = hashlib.sha1(f"{prefix}-{idx}".encode("utf-8")).hexdigest().upper()
            fake_suffix = fake_full_hash[5:]
            if fake_suffix in existing_suffixes:
                continue
            padding.append(f"{fake_suffix}:0")
        return padding

    def _send_text(self, status: int, payload: str) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_str: str, *args) -> None:
        # Keep test output clean.
        return


def first_or_empty(values):
    if not values:
        return ""
    return values[0] if values[0] is not None else ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local synthetic breach API test backend.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Bind port (default: 8787)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = ThreadingHTTPServer((args.host, args.port), MockPwnedHandler)
    print(f"Mock backend listening on http://{args.host}:{args.port}")
    print("Synthetic leak fixtures:")
    for passphrase, count in DEFAULT_LEAKED_PASSPHRASES.items():
        print(f"  - {passphrase!r}: {count}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
