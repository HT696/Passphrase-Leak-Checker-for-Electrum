"""Re-export the shared breach-checking client for Electrum."""

from passphrase_leak_checker.client import (
    LeakCheckError,
    LeakCheckOutcome,
    LeakCheckResult,
    MODE_FULL_HASH,
    MODE_K_ANONYMITY,
    MAX_HTTP_METADATA_BYTES,
    PwnedClient,
    SocksProxy,
    lookup_outcome,
)

__all__ = [
    "LeakCheckError", "LeakCheckOutcome", "LeakCheckResult",
    "MODE_FULL_HASH", "MODE_K_ANONYMITY", "PwnedClient", "lookup_outcome",
    "SocksProxy", "MAX_HTTP_METADATA_BYTES",
]
