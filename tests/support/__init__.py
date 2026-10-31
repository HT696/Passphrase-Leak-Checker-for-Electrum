"""Synthetic fixtures shared by unit and integration tests."""

import hashlib
from types import SimpleNamespace

HASH = hashlib.sha1(b"password").hexdigest().upper()
SUFFIX = HASH[5:]
OTHER = "0" * 35
ENDPOINT = "https://example.com/range/{prefix}"


def policy(offline=False, configured_proxy=False, active_proxy=False):
    config = SimpleNamespace(NETWORK_OFFLINE=offline, NETWORK_PROXY_ENABLED=configured_proxy)
    network = SimpleNamespace(get_parameters=lambda: SimpleNamespace(
        proxy=SimpleNamespace(enabled=active_proxy)))
    return config, network
