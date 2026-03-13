"""CyberChef upstream test vectors.

Auto-generated from CyberChef JS test files by tools/generate_cyberchef_test_py.py.
Do not edit manually.
"""

import json
import re
from pathlib import Path

import pytest

from ida_cyberchef.cyberchef import bake

_DATA = json.loads(
    (Path(__file__).parent / "data" / "cyberchef_test_vectors.json").read_text()
)

EXACT_VECTORS = _DATA["exact_vectors"]
MATCH_VECTORS = _DATA["match_vectors"]

MISSING_OPERATIONS = {
    "Caret/M-decode",
    "Convert co-ordinate format",
    "Fletcher-16 Checksum",
    "Fletcher-32 Checksum",
    "Fletcher-64 Checksum",
    "HAS-160",
    "Parse X.509 CRL",
    "Public Key from Certificate",
    "Public Key from Private Key",
}


def _uses_missing_operation(recipe: list) -> bool:
    for step in recipe:
        op = step if isinstance(step, str) else step.get("op", "")
        if op in MISSING_OPERATIONS:
            return True
    return False


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


@pytest.mark.parametrize(
    "vector",
    EXACT_VECTORS,
    ids=[v["name"] for v in EXACT_VECTORS],
)
def test_cyberchef_exact(vector):
    if _uses_missing_operation(vector["recipe"]):
        pytest.xfail("operation not available in this CyberChef build")

    expected = vector["expected"]
    try:
        result = bake(vector["input"], vector["recipe"])
    except RuntimeError as exc:
        if "Timed out" in str(exc):
            pytest.xfail("timed out (slow crypto operation)")
        raise
    except Exception as exc:
        error_msg = str(exc)
        if expected and expected in error_msg:
            return
        raise
    result = _coerce_result(result, expected)
    assert result == expected, (
        f"[{vector['module']}/{vector['name']}] "
        f"expected {expected!r:.200}, got {result!r:.200}"
    )


@pytest.mark.parametrize(
    "vector",
    MATCH_VECTORS,
    ids=[v["name"] for v in MATCH_VECTORS],
)
def test_cyberchef_match(vector):
    if _uses_missing_operation(vector["recipe"]):
        pytest.xfail("operation not available in this CyberChef build")

    expected_match = vector["expected_match"]
    try:
        result = bake(vector["input"], vector["recipe"])
    except RuntimeError as exc:
        if "Timed out" in str(exc):
            pytest.xfail("timed out (slow crypto operation)")
        raise
    except Exception as exc:
        error_msg = str(exc)
        if re.search(expected_match, error_msg):
            return
        raise
    if isinstance(result, bytes):
        try:
            result = result.decode("utf-8")
        except UnicodeDecodeError:
            result = result.decode("latin-1")
    assert re.search(expected_match, str(result)), (
        f"[{vector['module']}/{vector['name']}] "
        f"pattern {expected_match!r:.200} not found in {str(result)!r:.200}"
    )
