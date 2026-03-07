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

## Known unsupported but intended for future remediation

These operations are still shipped in metadata, but they are not currently reliable in this runtime:
- Magic
- YARA Rules
- Argon2
- Argon2 compare

These are not treated as out of scope. They need additional runtime or wasm packaging work.

## Known degraded behaviors still shipped

These operations currently have known behavior gaps and should not be treated as fully corrected:
- Reverse: character mode still corrupts some multibyte UTF-8 input
- Set Difference and Set Intersection: preserve duplicates from the first sample
- Median: odd-length behavior still needs an explicit policy decision or upstream fix
- Gzip: header checksum mode still needs investigation
- From Base: fractional inputs still fail
- Unescape Unicode Characters: `U+` decoding only handles the four-digit form reliably
- To Base92: returns bytes through the Python bridge rather than a Python string

## Support policy for docs and tests

- unsupported operations stay discoverable in internal metadata when they exist upstream
- unsupported operations should be called out explicitly in user-facing docs
- blocked regression tests should remain in place for unsupported operations and major runtime gaps
- deterministic offline behavior takes priority over browser parity
