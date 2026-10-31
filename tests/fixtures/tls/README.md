# Public TLS test fixtures

These certificates and `server-key.pem` are public, disposable test material.
Never use the key for a real service or install this CA in a system trust store.
Tests trust the CA only inside their own in-memory client SSL context.

The certificates identify `service.leak-checker.invalid`. `server.pem` is valid
from 2020 to 2100; `expired.pem` expires in 2021; `future.pem` is valid from 2098
to 2099. They share a public test key and are signed by `ca.pem`. The CA private
key is not retained. Fixtures use RSA-2048 and SHA-256; running the tests needs
only Python's standard library.

Tests exchange real TLS records with `ssl.MemoryBIO`, without DNS, socket
connections or public services. Runtime certificates and platform trust stores
require separate host validation. Test keys and certificates are excluded from
the plugin ZIP.
