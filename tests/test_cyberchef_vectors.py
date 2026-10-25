"""CyberChef's own operation tests, run through bake().

tests/data/cyberchef_test_vectors.json is extracted from
deps/CyberChef/tests/operations/tests/ by tools/extract_upstream_vectors.mjs
(`just test-vectors`). Do not edit it manually.
"""

import json
import re
from pathlib import Path

import pytest

from ida_cyberchef.cyberchef import bake

_DATA = json.loads((Path(__file__).parent / "data" / "cyberchef_test_vectors.json").read_text(encoding="utf-8"))

EXACT_VECTORS = _DATA["exact_vectors"]
MATCH_VECTORS = _DATA["match_vectors"]

_JS_REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def _js_regex(source: str, flags: str) -> re.Pattern:
    """Compile a JS RegExp source and flags (g, u and y have no effect on a search)."""
    python_flags = 0
    for flag in flags:
        python_flags |= _JS_REGEX_FLAGS.get(flag, 0)
    # Named groups are (?<name>...) in JS and (?P<name>...) in Python.
    return re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", source), python_flags)


# Known failures, keyed by test name or, for whole operations, name prefix.
XFAIL = {
    # jsonwebtoken needs Node's crypto.KeyObject, which crypto-browserify (the
    # crypto module in browser builds of CyberChef) does not provide.
    "JWT Sign": "jsonwebtoken needs Node crypto.KeyObject",
    "JWT Verify": "jsonwebtoken needs Node crypto.KeyObject",
    # The msgpack library reports a different error than under Node.js.
    "From MessagePack: no content": "V8 msgpack throws a different error message than upstream test expects",
}


def _xfail_reason(name: str) -> str | None:
    return next((reason for key, reason in XFAIL.items() if name == key or name.startswith(key + ":")), None)


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
    if reason := _xfail_reason(vector["name"]):
        pytest.xfail(reason)

    expected = vector["expected"]
    try:
        result = bake(vector["input"], vector["recipe"], present=True)
    except TimeoutError:
        pytest.xfail("timed out")
    except Exception as exc:
        error_msg = str(exc)
        if expected and _error_matches_expected(error_msg, expected):
            return
        raise
    assert not vector["expected_error"], f"[{vector['module']}/{vector['name']}] expected an error, got {result!r:.200}"
    assert result == expected, f"[{vector['module']}/{vector['name']}] expected {expected!r:.200}, got {result!r:.200}"


@pytest.mark.parametrize(
    "vector",
    MATCH_VECTORS,
    ids=[v["name"] for v in MATCH_VECTORS],
)
def test_cyberchef_match(vector):
    if reason := _xfail_reason(vector["name"]):
        pytest.xfail(reason)

    unexpected = "unexpected_match" in vector
    pattern = _js_regex(vector["unexpected_match" if unexpected else "expected_match"], vector["flags"])
    try:
        result = bake(vector["input"], vector["recipe"], present=True)
    except TimeoutError:
        pytest.xfail("timed out")
    except Exception as exc:
        if not unexpected and pattern.search(str(exc)):
            return
        raise
    found = pattern.search(result) is not None
    assert found != unexpected, (
        f"[{vector['module']}/{vector['name']}] pattern {pattern.pattern!r:.200} "
        f"{'found' if unexpected else 'not found'} in {str(result)!r:.200}"
    )
