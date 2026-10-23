# JavaScript engine choice

ida-cyberchef runs CyberChef's Node-targeted bundle in an embedded JavaScript engine. Since 2026-10 that engine is [mini-racer](https://github.com/bpcreech/PyMiniRacer) (V8). This note records why, so the next re-evaluation can start from it.

## Requirements

- Prebuilt wheels for CPython 3.10 to 3.15, so installing never compiles code or runs npm.
- Windows x86_64, macOS arm64 and Linux x86_64. hcli bundles also target Linux aarch64, and need glibc 2.28 or older on Linux.
- Installable offline from a wheelhouse.
- Modern JavaScript (ES2020 and later): the bundle uses classes, async functions, BigInt, typed arrays and regex lookbehind. Some operations use `Intl` or WebAssembly.

## History

1. STPyV8 (V8, Boost.Python). Archived in 2026.
2. PythonMonkey (SpiderMonkey). It depends on `pminit`, which PyPI has only as an sdist that runs `npm install` when it is built, so pip needs npm, and `pip download --only-binary :all:` (used by hcli bundles) fails. Its Linux wheels also need glibc 2.31. Its wheels read CPython internals, which broke on 3.13.0 to 3.13.12 and 3.14.0.
3. mini-racer (V8 14.4). Current.

## Candidates considered (2026-10)

| Engine | PyPI | Wheels | Verdict |
|---|---|---|---|
| V8 | `mini-racer` 0.14.1 | `py3-none` per platform (ctypes), including win_amd64, macosx_11_0_arm64, manylinux_2_27 x86_64 and aarch64 | chosen |
| QuickJS-ng | `quickjs-ng` | `cp310-abi3` | fallback: no `Intl`, no WebAssembly, interpreter only |
| QuickJS | `quickjs` | up to cp312 | archived |
| V8 | `stpyv8` | no cp315 | archived |
| V8 (deno_core) | `jsrun`, `pydeno` | no Windows, or gaps on 3.15 | not viable |
| QuickJS-ng in wasmtime | `quickjs-rs` | requires Python 3.11 or newer | not viable |
| Duktape | `dukpy`, `pyduktape2` | | ES5 only |
| MicroQuickJS | none | | ES5 subset, no Python package |
| Deno, Node | `deno`, `nodejs-wheel-binaries` | `py3-none` | out of process; last resort |

mini-racer does not use the CPython C API, so a wheel works with every CPython version, including ones released after the wheel. It ships V8 with ICU data, so `Intl` and `localeCompare` behave as in Node.

## How the bridge works

mini-racer runs V8 on its own thread. From Python to JS it passes only primitives and handles to JS objects. From JS to Python it returns ArrayBuffers as zero-copy `memoryview`s. Therefore:

- `ida_cyberchef/data/runtime.js` adds the browser and Node.js APIs that bare V8 lacks: timers, `atob`/`btoa`, `TextEncoder`/`TextDecoder` and `crypto.getRandomValues`. It also defines the `__pi*` helpers that the bridge calls.
- Bytes go into JS as latin-1 strings and come out as ArrayBuffers. Dicts and lists go in as JSON.
- JS cannot call Python synchronously. `crypto.getRandomValues` is a ChaCha20 stream, keyed with `os.urandom` when the bundle loads and before every bake.

## Known caveats

- mini-racer has one maintainer and releases a few times a year. Its ctypes structures trigger a `DeprecationWarning` on Python 3.15, which becomes an error on 3.19 (`_pack_` without `_layout_`).
- The wheels are about 15 to 22 MB each.
