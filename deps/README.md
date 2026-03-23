We use a fork of CyberChef at https://github.com/williballenthin/CyberChef, branch `ida-cyberchef-fixes`. The submodule points to this fork directly.

The fork contains two fixes on top of upstream CyberChef:
- **Async wrapper** (`src/node/api.mjs`): the sync operation wrapper detects and resolves promise results from Babel-transpiled async operations
- **Highlight guard** (`src/core/Utils.mjs`): `window.app.options.attemptHighlight = false` is wrapped in a safe conditional for environments where `window.app.options` may not exist

These fixes live as commits in the fork — no build-time or runtime patching is needed.

## Build/runtime contract

The bundle (`ida_cyberchef/data/CyberChef.js`) is built with `just build`, which runs `npm run node` in the submodule and copies the output. The Python runtime loads the bundle without modification.

The Python runtime (`ida_cyberchef/cyberchef.py`) provides the minimal JS environment:
- `globalThis.app` with `alert` — CyberChef expects a web-like app object
- Timer/process/crypto polyfills — the bundle assumes a Node-like environment
- CommonJS `module.exports` — the bundle is built as a CommonJS module

When updating the CyberChef fork or rebuilding the bundle:
1. Make changes in the submodule, commit, and push to the fork
2. Run `just build`
3. The resulting `CyberChef.js` is loaded directly — no patching
