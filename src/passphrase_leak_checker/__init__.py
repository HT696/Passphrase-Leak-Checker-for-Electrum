"""Host-independent breach-checking client."""

__version__ = "0.1.0"

from .client import (
    LeakCheckError,
    LeakCheckOutcome,
    LeakCheckResult,
    MODE_FULL_HASH,
    MODE_K_ANONYMITY,
    PwnedClient,
    SocksProxy,
    lookup_outcome,
)

__all__ = [
    "LeakCheckError", "LeakCheckOutcome", "LeakCheckResult",
    "MODE_FULL_HASH", "MODE_K_ANONYMITY", "PwnedClient", "lookup_outcome",
    "SocksProxy",
]
