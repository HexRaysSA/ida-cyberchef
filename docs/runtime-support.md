# Runtime support

This project ships CyberChef through an STPyV8-backed runtime inside Python and Qt. Most offline operations work. Some classes of operations are intentionally unsupported in the current runtime, and some remain known gaps.

## Supported model

The supported path is:
- local, deterministic operation execution
- no browser tab, DOM, worker, or network dependency
- no external asset fetch at runtime

The bridge applies local compatibility fixes for CyberChef's Node-targeted bundle, including argument normalization and runtime polyfills.

## Unsupported in the current runtime

These operations are intentionally unsupported unless the runtime model changes:
- JavaScript Beautify
- JavaScript Minify
- JavaScript Parser
- Syntax highlighter
- DNS over HTTPS
- HTTP request
- Optical Character Recognition
- Add Text To Image

Reasons:
- the JavaScript formatting/highlighting operations are excluded by the current Node-targeted CyberChef bundle
- the network operations require browser-style request APIs and live network policy decisions
- the OCR and image-text operations require browser-style workers, assets, or XHR-style loading that this project does not provide

## Also unsupported in the current runtime

These operations remain unsupported in the current runtime and should be documented that way rather than treated as active remediation targets:
- Magic
- YARA Rules
- Argon2
- Argon2 compare

They may stay discoverable in internal metadata, but user-facing docs should describe them as unsupported.

## Missing from the CyberChef build

These operations exist in upstream CyberChef but are absent from the Node-targeted bundle shipped with this project. They are not in the operation schema and cannot be called at runtime:
- Caret/M-decode
- Convert co-ordinate format
- Fletcher-16 Checksum
- Fletcher-32 Checksum
- Fletcher-64 Checksum
- HAS-160
- Parse X.509 CRL
- Public Key from Certificate
- Public Key from Private Key

These were discovered by importing upstream test vectors (see `tests/test_cyberchef_vectors.py`). Adding them requires rebuilding the CyberChef bundle with the corresponding operation modules included.

## Known degraded behaviors still shipped

No additional degraded behaviors are currently tracked in `remaining.md` for the supported runtime.

## Support policy for docs and tests

- unsupported operations stay discoverable in internal metadata when they exist upstream
- unsupported operations should be called out explicitly in user-facing docs
- blocked regression tests should remain in place for unsupported operations and major runtime gaps
- deterministic offline behavior takes priority over browser parity
