# Runtime support

ida-cyberchef runs CyberChef's own core, with all of its operations, in an embedded V8 engine ([mini-racer](https://github.com/bpcreech/PyMiniRacer)). Recipes run through CyberChef's `Recipe` class, as in the web app, so flow control (Fork, Merge, Subsection, Jump, Conditional Jump, Register, Return), argument defaults and escape handling (`\n`, `\x00` in binary-string arguments) behave as in the web app.

## Supported model

The supported path is:
- local, deterministic operation execution
- no browser tab, DOM, worker, or network dependency
- no external asset fetch at runtime

CyberChef runs in its browser (Web Worker) mode. `js/polyfills.mjs` provides the Web APIs that a bare V8 engine lacks: timers, `atob`/`btoa`, `TextEncoder`/`TextDecoder`, `crypto.getRandomValues`, and `Blob`/`File`/`FileReader`.

## Unsupported operations

- DNS over HTTPS
- HTTP request
- Optical Character Recognition
- Add Text To Image
- JWT Sign
- JWT Verify

Reasons:
- The network operations need the browser's `fetch` API and network access, which the runtime deliberately does not provide.
- Optical Character Recognition needs browser workers and OCR assets that this project does not ship.
- Add Text To Image loads its bitmap fonts with `fetch`.
- JWT Sign and JWT Verify use jsonwebtoken, which needs Node's `crypto.KeyObject`. Browser builds of CyberChef use crypto-browserify, which does not provide it. JWT Decode works because it only parses the token.

These operations stay in the operation schema, and `docs/ops.md` marks them as unsupported. A recipe that uses one fails with the operation's error message.

## Known differences from the web app

- Operations that render HTML for the web app's output pane (Bombe, Multiple Bombe, Index of Coincidence, Play Media) return their underlying data instead: JSON, a number, or bytes.
- `crypto.subtle` is not available.

## Support policy for docs and tests

- unsupported operations stay discoverable in internal metadata when they exist upstream
- unsupported operations should be called out explicitly in user-facing docs
- blocked regression tests should remain in place for unsupported operations
- deterministic offline behavior takes priority over browser parity
