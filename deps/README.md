We use a fork of CyberChef at https://github.com/williballenthin/CyberChef, branch `ida-cyberchef-fixes`. The submodule points to this fork directly.

The fork carries the following patches on top of upstream (`gchq/CyberChef`):

**Build system changes:**
- `update JS import syntax` -- replace deprecated `assert` with `with` in import assertions
- `add CommonJS build for a minimal JS interpreter` -- adds `webpack.node.config.js` and browserify polyfills so the bundle works in non-Node JS runtimes (STPyV8, PythonMonkey)
- `fix: inject process.versions.node at build time` -- makes `isNodeEnvironment()` true during bundling so Node code paths are included in the output

**Operation bug fixes** (found via our test suite):
- `Fix empty Modhex input`
- `Fix TLV BER lengths`
- `fix DechunkHTTPResponse trailers`
- `fix UnescapeUnicodeCharacters with U+ encoding`
- `fix Set operations uniq'ing items`
- `fix gzip with comment and checksum`
- `fix FromBase with fractional inputs`
- `fix Median for odd lengthed inputs`

**Runtime compatibility fixes:**
- `fix: handle promise results in sync operation wrapper` -- after Babel transpilation, async operations return promises without the AsyncFunction constructor identity; the sync wrapper must detect and resolve these
- `fix: guard window.app.options access for minimal runtimes` -- guard `window.app.options` access for environments where `window` exists but `app.options` may not

## Build/runtime contract

The bundle (`ida_cyberchef/data/CyberChef.js`) is built with `just build`, which runs `npm run node` in the submodule and copies the output. The Python runtime loads the bundle without modification.

The Python runtime (`ida_cyberchef/cyberchef.py`) provides the minimal JS environment:
- `globalThis.app` with `alert` -- CyberChef expects a web-like app object
- Timer/process/crypto polyfills -- the bundle assumes a Node-like environment
- CommonJS `module.exports` -- the bundle is built as a CommonJS module

When updating the CyberChef fork or rebuilding the bundle:
1. Make changes in the submodule, commit, and push to the fork
2. Run `just build`
3. The resulting `CyberChef.js` is loaded directly -- no patching
