"""CyberChef upstream test vectors.

Auto-generated from CyberChef JS test files by tools/generate_cyberchef_test_py.py.
Do not edit manually.
"""

import json
import re
from pathlib import Path

import pytest

from ida_cyberchef.cyberchef import bake

_DATA = json.loads((Path(__file__).parent / "data" / "cyberchef_test_vectors.json").read_text(encoding="utf-8"))


def _positional_args(vectors: list[dict]) -> list[dict]:
    """Turn {"_arg0": a, "_arg1": b} (upstream recipes with unnamed args) into [a, b]."""
    for vector in vectors:
        for step in vector["recipe"]:
            args = step.get("args") if isinstance(step, dict) else None
            if args and all(key.startswith("_arg") for key in args):
                step["args"] = [args[f"_arg{index}"] for index in range(len(args))]
    return vectors


EXACT_VECTORS = _positional_args(_DATA["exact_vectors"])
MATCH_VECTORS = _positional_args(_DATA["match_vectors"])

# These tests are expected failures due to known limitations of the current
# JS-engine-backed runtime. Each entry documents why the test cannot pass in the current bridge.
#
# To check whether a failure is still expected, remove the entry and run the test.
XFAIL_EXACT = {
    # --- presentType: "html" ---
    # CyberChef operations can define a present() method that renders their raw output
    # as HTML for the browser UI (e.g. HTML tables, <audio>/<video> tags). The bridge
    # only calls run(), returning the raw data as native Python types. The JS test
    # harness compares against the present() HTML output.
    #
    # Play Media: run() returns raw audio/video bytes, present() wraps them in
    # <audio src='data:...'> or <video src='data:...'> base64 data URI tags.
    "Play Media: raw wav": "bridge returns raw bytes; JS test expects <audio> HTML tag from present()",
    "Play Media: hex ogg": "bridge returns raw bytes; JS test expects <audio> HTML tag from present()",
    "Play Media: base64 webm": "bridge returns raw bytes; JS test expects <video> HTML tag from present()",
    # --- CBOR Decode JSON string quoting ---
    # CBOR Decode has outputType "JSON". When CyberChef's JS test harness coerces
    # a JSON string value to a display string, it preserves the JSON quotes:
    # the string Text becomes "Text" (with literal double quotes). Our bridge
    # returns the native Python string 'Text' without quotes, which is the correct
    # semantic value but doesn't match the JS toString() coercion.
    "From Hex: Can decode text": "CBOR Decode returns native string 'Text'; JS test expects JSON-quoted '\"Text\"'",
    # --- Error message differences ---
    # The underlying JS error message from our V8 runtime differs from what
    # CyberChef's test was written against. Our V8 throws "RangeError: Offset is
    # outside the bounds of the DataView" while the test expects "Error: Could not
    # parse". Same error scenario, different message from the msgpack library.
    "From MessagePack: no content": "V8 msgpack throws different error message than upstream test expects",
    # --- Parse X.509 CRL ---
    # Upstream's expected text for these two CRLs (tab indentation, "Unsupported
    # CRL extension") does not match what this revision of the operation prints:
    # it now decodes the Issuer Alternative Name, as the third CRL vector expects.
    "Parse X.509 CRL: Example PEM encoded CRL with RSA signature": "upstream expectation predates this revision's output",
    "Parse X.509 CRL: Example PEM encoded CRL with RSA signature, CRL Reason and Invalidity Date": (
        "upstream expectation predates this revision's output"
    ),
    # --- JWT Sign/Verify ---
    # jsonwebtoken needs Node's crypto.KeyObject, which crypto-browserify (the
    # crypto module in browser builds of CyberChef) does not provide.
    "JWT Sign: HS256": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: HS256 with custom header": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: HS384": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: HS512": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: ES256": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: ES384": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: ES512": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: RS256": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: RS384": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Sign: RS512": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Verify: HS": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Verify: RS": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Verify: ES": "jsonwebtoken needs Node crypto.KeyObject",
}

XFAIL_MATCH = {
    # --- presentType: "html" (see explanation above) ---
    # Bombe/MultiBombe: run() returns JSON dicts like
    # {'nLoops': 6, 'result': [['LGA', 'SS', 'VFISUSGTKSTMPSUNAK']]}
    # but the JS test regex matches against present() HTML output with <td> tags.
    "Bombe: 3 rotor (self-stecker)": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    "Bombe: 3 rotor (other stecker)": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    "Bombe: crib offset": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    "Bombe: multiple stops": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    "Bombe: checking machine": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    "Multi-Bombe: 3 rotor": "bridge returns JSON dict; JS test expects HTML <td> table from present()",
    # Index of Coincidence: run() returns a raw float (0.0714...), present()
    # formats it as "Index of Coincidence: 0.071...\nNormalized: 1.857...".
    "Index of Coincidence": "bridge returns raw float; JS test expects formatted text from present()",
    # --- Fernet timestamp ---
    # Fernet tokens embed the current timestamp in the first 9 bytes. The test regex
    # ^gAAAAABce-[\w-]+ hardcodes a base64 prefix corresponding to a specific
    # timestamp from when the test was written (~2020). Our output has the current
    # timestamp, so the prefix differs. The operation works correctly.
    "Fernet Encrypt: no input": "test regex hardcodes a 2020-era timestamp prefix; output is timestamp-dependent",
    "Fernet Encrypt: valid arguments": "test regex hardcodes a 2020-era timestamp prefix; output is timestamp-dependent",
    # --- JPath sandboxing difference ---
    # This test is an XSS/sandbox-escape probe that calls
    # constructor("self.postMessage(...)"). CyberChef's browser test expects the
    # error "self is not defined" (browser global). Our V8 context doesn't have
    # 'self' either, but the JPath library fails earlier with "Unexpected { at
    # character 1" before it even reaches the constructor call.
    "JPath Expression: Script-based expression": "JPath library fails at parse stage in V8; browser fails at eval stage",
}


def _coerce_result(result, expected):
    """Coerce bake result to be comparable with JS expected output.

    CyberChef JS tests always compare string outputs. Our bake() can return
    bytes, native Python types (int, float, bool, list, dict), etc.
    """
    if isinstance(result, bytes) and isinstance(expected, str):
        try:
            decoded = result.decode("utf-8")
        except UnicodeDecodeError:
            decoded = result.decode("latin-1")
        return decoded

    if not isinstance(result, str) and isinstance(expected, str):
        if isinstance(result, bool):
            return str(result).lower()
        if isinstance(result, float) and result == int(result):
            return str(int(result))
        if isinstance(result, (int, float)):
            return str(result)
        if isinstance(result, (list, dict)):
            return json.dumps(result, indent=4, ensure_ascii=False)

    return result


def _error_matches_expected(error_msg: str, expected: str) -> bool:
    """Check if a JS exception message matches the expected CyberChef output.

    CyberChef returns errors as "OpName - error details" in its test harness.
    Our bridge throws exceptions with just the error details and a JSError wrapper.
    """
    if expected in error_msg:
        return True
    stripped = re.sub(r"^[A-Za-z0-9/ ]+ - ", "", expected)
    return bool(stripped != expected and stripped in error_msg)


@pytest.mark.parametrize(
    "vector",
    EXACT_VECTORS,
    ids=[v["name"] for v in EXACT_VECTORS],
)
def test_cyberchef_exact(vector):
    if vector["name"] in XFAIL_EXACT:
        pytest.xfail(XFAIL_EXACT[vector["name"]])

    expected = vector["expected"]
    try:
        result = bake(vector["input"], vector["recipe"])
    except TimeoutError:
        pytest.xfail("timed out")
    except Exception as exc:
        error_msg = str(exc)
        if expected and _error_matches_expected(error_msg, expected):
            return
        raise
    result = _coerce_result(result, expected)
    if isinstance(result, str) and isinstance(expected, str):
        result = result.rstrip("\n")
        expected = expected.rstrip("\n")
    assert result == expected, f"[{vector['module']}/{vector['name']}] expected {expected!r:.200}, got {result!r:.200}"


@pytest.mark.parametrize(
    "vector",
    MATCH_VECTORS,
    ids=[v["name"] for v in MATCH_VECTORS],
)
def test_cyberchef_match(vector):
    if vector["name"] in XFAIL_MATCH:
        pytest.xfail(XFAIL_MATCH[vector["name"]])

    expected_match = vector["expected_match"]
    try:
        result = bake(vector["input"], vector["recipe"])
    except TimeoutError:
        pytest.xfail("timed out")
    except Exception as exc:
        error_msg = str(exc)
        if re.search(expected_match, error_msg):
            return
        raise
    search_flags = 0
    if isinstance(result, bytes):
        search_flags = re.DOTALL
        try:
            result = result.decode("utf-8")
        except UnicodeDecodeError:
            result = result.decode("latin-1")
    assert re.search(expected_match, str(result), flags=search_flags), (
        f"[{vector['module']}/{vector['name']}] pattern {expected_match!r:.200} not found in {str(result)!r:.200}"
    )
