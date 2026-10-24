# IDA CyberChef

A Qt-based CyberChef interface designed for malware analysis workflows in IDA Pro. This brings the power of [CyberChef](https://gchq.github.io/CyberChef/)'s data transformation operations directly into your reverse engineering toolkit.

**Install it** via Hex-Rays' IDA Pro plugin manager:

```console
hcli plugin install ida-cyberchef
```

[HCLI](https://hcli.docs.hex-rays.com) is the official Hex-Rays tool for managing IDA Pro installations, licenses, and SDKs.

![ida-cyberchef screenshot](docs/screenshot1.png)


## What is this?

If you've ever been knee-deep in a malware sample and needed to quickly decode some base64, XOR a blob with a key, or chain together a series of transformations on binary data - you know the pain of context switching. Copy data from IDA, paste into CyberChef web UI, get result, copy back. Repeat 47 times.

This project eliminates that workflow. It embeds CyberChef's data transforms directly into IDA Pro's Qt user interface, integrating with common IDA features, like reading the current cursor/selection, settings comments, and patching bytes.

## How it works

We use [mini-racer](https://github.com/bpcreech/PyMiniRacer) (V8, Chrome's JS engine) to run CyberChef's JavaScript code inside Python. `ida_cyberchef/data/CyberChef.js` bundles CyberChef's core (every operation), polyfills for the few Web APIs that a bare V8 engine lacks, and a small bridge (`js/`). The `ida_cyberchef.cyberchef` module loads it and exposes a `bake()` function that takes text or bytes and a recipe. Recipes run through CyberChef's own `Recipe` class, so flow control (Fork, Jump, Register, ...), argument defaults and escape handling match the web app.

Then, we have a PySide6 Qt widget that exposes the recipe composer with the input/output hex dumps. The UI updates reactively - change the input or tweak an operation argument, and after a brief debounce, the entire pipeline re-executes and updates the output.

As a minor extension beyond traditional CyberChef, each operation step can be expanded to preview intermediate results, which might be useful for debugging complex recipes.

## Background

This started as an experiment to see if CyberChef could be embedded in Python without needing a browser or Electron. The GCHQ team built CyberChef as a web application, but they also exposed a Node.js API. We're using a minimal CommonJS-compatible build (from Willi Ballenthin's fork) that doesn't require the full Node.js runtime.

The project went through a few iterations:
1. First, just getting the JavaScript engine to work with proper type conversions between Python bytes and CyberChef's "Dish" objects
2. Then building a clean `bake()` API that chains operations
3. Then the Qt layer with reactive execution

There's also a standalone (non-IDA Pro) Qt application for running CyberChef on the desktop; but really, I'm not sure why you'd use this versus the standalone HTML file from upstream.

## Runtime support

The runtime supports local, deterministic operation execution. It has no browser tab, DOM, worker, or network dependency, and does not fetch external assets at runtime. All 506 CyberChef operations are included. Six are known not to work:

Unsupported operations: DNS over HTTPS and HTTP request (they need network access), Optical Character Recognition and Add Text To Image (they load assets with browser APIs), and JWT Sign and JWT Verify (they need Node's `crypto.KeyObject`). `docs/runtime-support.md` has the details, and `docs/ops.md` marks these operations.

## Supported Python versions

Python 3.10 through 3.15, on Windows x86_64, macOS arm64 and Linux x86_64.

mini-racer loads V8 as a plain shared library through `ctypes` and does not use the CPython C API, so it ships one `py3-none` wheel per platform that works with every Python version. All runtime dependencies (`mini-racer`, `pydantic`) install from prebuilt wheels, with no compiler, Node.js or npm needed. To install offline, build a wheelhouse on a connected machine and copy it over:

```
python -m pip download --only-binary :all: --dest wheelhouse "mini-racer>=0.14.1" "pydantic>=2"
python -m pip install --no-index --find-links wheelhouse "mini-racer>=0.14.1" "pydantic>=2"
```

To build a wheelhouse for other platforms or Python versions, add `--platform` (for example `win_amd64`, `macosx_11_0_arm64`, or `manylinux_2_27_x86_64 --platform manylinux_2_17_x86_64`) and `--python-version`. Linux needs glibc 2.27 or newer.

## Building

First, initialize the submodule if you haven't already:

```bash
git submodule update --init --recursive
```

Then build CyberChef's JavaScript bundle (you'll need Node.js and npm for this, but only to build; the plugin itself does not need them):

```bash
just build
```

This installs npm dependencies in the CyberChef submodule, generates CyberChef's operation config, bundles `js/bridge.mjs` with CyberChef's core into `ida_cyberchef/data/CyberChef.js` (about 20 seconds; a ~34MB file), and regenerates `operation_schema.json`, `docs/ops.md` and the test vectors extracted from CyberChef's own test suite. The build is reproducible, and CI checks that the committed bundle matches its sources.

To run the plugin in IDA, symlink the development directory into `$IDAUSR/plugins/ida-cyberchef`:

```
ln -s (pwd) ~/.idapro/plugins/ida-cyberchef
```

You'll also want to install the dependencies into your IDA Pro Python virtual environment, something like:

```
~/.idapro/venv/bin/python -m pip install mini-racer pydantic
```

Also, you can run the standalone QApplication (outside of IDA Pro) like this:

```bash
uv run cyberchef-qt
```

## Future Work

I'm not quite sure if this will survive or not - I started out to prove this could work, and then was surprised when things fell into place. The architecture is a little ugly: running V8 from Python inside IDA to load a huge blob from GCHQ. But, it works, and we benefit from the operations already supported by CyberChef. So, if you want to propose enhancements and bug fixes, go for it!

There's some risk that the underlying Javascript engine (mini-racer now; PythonMonkey before that, whose `pminit` dependency needed npm at install time; STPyV8 before that, until it was archived in 2026) might become unmaintained or not build/work with future versions of Python or IDA Pro. That'll be a good time to re-evaluate the best parts of ida-cyberchef and perhaps rebuild them carefully. [docs/js-engine.md](docs/js-engine.md) records the engines considered in the last evaluation.

## License

This project's code is licensed Apache 2.0 by Hex-Rays. CyberChef itself is also licensed under Apache 2.0 by GCHQ.
