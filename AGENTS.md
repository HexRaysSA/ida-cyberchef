# Repository guide

## Start here

- `ida_cyberchef/cyberchef.py`: Python side of the bridge. Loads `CyberChef.js` into V8 (mini-racer) and exposes `bake()`.
- `js/bridge.mjs`: JS side of the bridge. Maps named arguments to CyberChef's positional ones and runs recipes with CyberChef's core `Recipe` class.
- `tests/test_operation_vectors.py`: declarative real-engine operation tests. This is the pattern to extend for coverage.
- `tests/test_cyberchef.py`: imperative coverage of `bake()` and the bridge's argument handling.
- `tests/test_cyberchef_vectors.py`: CyberChef's own operation tests, run through `bake(..., present=True)` and compared as upstream's harness does.
- `docs/plans/test-vector-expansion.md`: follow-on plan for expanding operation coverage.

## Repo map

### Runtime package

- `ida_cyberchef/__init__.py`: package exports. Qt objects are imported lazily so non-Qt tests can run without GUI dependencies.
- `ida_cyberchef/cyberchef.py`: mini-racer (V8) integration and the `bake()` entrypoint.
- `ida_cyberchef/cyberchef_widget.py`: top-level Qt widget wiring the whole UI together.
- `ida_cyberchef/main.py`: standalone Qt app entrypoint.
- `ida_cyberchef/plugin/__init__.py`: IDA plugin entrypoint.

### Core logic

- `ida_cyberchef/core/input_parser.py`: text, hex, and base64 input parsing.
- `ida_cyberchef/core/recipe_executor.py`: stepwise execution over a recipe.
- `ida_cyberchef/core/operation_registry.py`: loads and searches the generated operation schema.
- `ida_cyberchef/core/recipe_models.py`: Pydantic recipe serialization models.
- `ida_cyberchef/core/hex_formatter.py`: hex dump formatting helpers.
- `ida_cyberchef/core/operation_doc_formatter.py`: text formatting for operation docs.

### Qt models

- `ida_cyberchef/qt_models/input_model.py`: input source and format state.
- `ida_cyberchef/qt_models/recipe_model.py`: ordered recipe state.
- `ida_cyberchef/qt_models/execution_model.py`: debounced execution coordinator.

### Widgets

- `ida_cyberchef/widgets/input_panel.py`: input source and input format UI.
- `ida_cyberchef/widgets/recipe_panel.py`: recipe editor and previews.
- `ida_cyberchef/widgets/output_panel.py`: output preview and IDA actions.
- `ida_cyberchef/widgets/operation_browser_widget.py`: searchable operation browser.
- `ida_cyberchef/widgets/operation_step_widget.py`: per-step argument editor.
- `ida_cyberchef/widgets/location_input_widget.py`: IDA location-based input selector.
- `ida_cyberchef/widgets/operation_search_dialog.py`, `insert_indicator_widget.py`: supporting UI pieces.

### Data and generated artifacts

- `ida_cyberchef/data/CyberChef.js`: CyberChef core, polyfills and bridge, built from `js/` by `just build`. Do not edit; it is checked in so that the plugin needs no npm.
- `ida_cyberchef/data/operation_schema.json`: generated operation metadata used by the UI and tests.
- `docs/ops.md`: rendered operation reference.

### Tools and upstream sources

- `js/bridge.mjs`: bundle entry point; exposes `globalThis.cyberchef.bake()`.
- `js/polyfills.mjs`: Web APIs a bare V8 lacks (timers, atob/btoa, TextEncoder/TextDecoder, URL, crypto.getRandomValues, crypto.subtle.digest, Blob/File/FileReader). Imported first.
- `js/build.cjs`: webpack build; uses webpack and npm packages from `deps/CyberChef/node_modules`.
- `tools/generate_operation_schema.py`: generates the schema from CyberChef's `OperationConfig.json` and `Categories.json`.
- `tools/generate_docs.py`: renders `docs/ops.md`.
- `tools/extract_upstream_vectors.mjs`: extracts CyberChef's own operation tests into `tests/data/cyberchef_test_vectors.json`.
- `deps/CyberChef/`: CyberChef submodule, tracking gchq/CyberChef `master` directly, with no fork. Tests that fail because of upstream bugs are marked xfail with the reason (`UPSTREAM_BUG_XFAILS`, `XFAIL`).
- `justfile`: `just build` installs npm dependencies, generates CyberChef's config, rebuilds `CyberChef.js`, and regenerates the schema, `docs/ops.md` and the upstream test vectors. The build is reproducible; CI checks that the committed outputs match.

### Tests

Non-Qt tests:

- `tests/test_cyberchef.py`
- `tests/test_operation_vectors.py`
- `tests/test_recipe_executor.py`
- `tests/test_operation_registry.py`
- `tests/test_input_parser.py`
- `tests/test_recipe_models.py`
- `tests/test_hex_formatter.py`
- `tests/test_operation_doc_formatter.py`
- `tests/test_generate_operation_schema.py`

Qt tests:

- `tests/test_qt_*.py`
- `tests/test_*panel.py`
- `tests/test_*widget.py`
- `tests/test_ui_verification.py`

## Test harness behavior

- Qt tests are disabled by default in pytest config.
- Use `IDA_CYBERCHEF_ENABLE_QT_TESTS=1 .venv/bin/python tools/run_pytest.py` to re-enable Qt collection and load `pytest-qt`.
- Default non-Qt test runs exercise the real mini-racer (V8) backed CyberChef engine.

## Practical workflow

- Use `.venv/bin/python` for installs and test runs.
- Run non-Qt tests with `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q`.
- Run Qt tests only through `IDA_CYBERCHEF_ENABLE_QT_TESTS=1 QT_QPA_PLATFORM=offscreen .venv/bin/python tools/run_pytest.py -q`.
- Rebuild with `just build` after changing `js/` or the CyberChef submodule (needs Node.js and npm). To update CyberChef, run `git submodule update --remote deps/CyberChef`, run `just build` and the tests, and commit the new submodule commit with the rebuilt outputs. Mark tests broken by upstream bugs as xfail rather than patching CyberChef.
- For operation coverage work, inspect both `operation_schema.json` and `docs/ops.md` before adding vectors.

## Operation test triage notes

- `tests/test_operation_vectors.py` is the preferred place for new deterministic engine coverage. Keep helpers small and value-oriented, then add parametrized `BakeVector` entries.
- Upstream operation implementations live under `deps/CyberChef/src/core/operations/`. When behavior is unclear, also inspect supporting code in `deps/CyberChef/src/core/lib/`.
- `docs/ops.md` uses upstream JS method names such as ``cartesianProduct()`` while the schema and recipes use user-facing names such as `Cartesian Product`. Search both styles when cross-referencing docs and source.
- Do not trust default arguments blindly when verifying operations through `bake()`. Explicit recipe args were required to exercise `Cartesian Product` correctly with newline delimiters during test work.
- Arithmetic operations like `Divide`, `Mean`, `Median`, and `Multiply` return CyberChef `BigNumber` objects internally; `bake()` returns them as `str`. Output conversion lives in `exportDish()` in `js/bridge.mjs` and the end of `bake()` in `cyberchef.py`.
- Arguments may be given by name (case and spaces ignored) or as a positional list, as in recipes exported from the web app. Missing arguments take the web app's defaults; binary-string arguments are escape-decoded by CyberChef itself.
- The `Median` upstream implementation in `deps/CyberChef/src/core/lib/Arithmetic.mjs` only sorts even-length inputs before taking the middle value. Treat odd-length median cases carefully until that behavior is confirmed or fixed.
