import hashlib
import uuid

import pytest

from ida_cyberchef.cyberchef import CyberChefError, bake


def test_from_base64():
    assert bake("U28gbG9uZyBhbmQgdGhhbmtzIGZvciBhbGwgdGhlIGZpc2gu", ["From Base64"]) == (
        b"So long and thanks for all the fish."
    )


def test_to_hex():
    assert bake(b"hello", ["To Hex"]) == "68 65 6c 6c 6f"


def test_md5():
    assert bake(b"hello", ["MD5"]) == "5d41402abc4b2a76b9719d911017c592"


def test_translate_datetime():
    result = bake(
        "15/06/2015 20:45:00",
        [{"op": "Translate DateTime Format", "args": {"Output timezone": "Australia/Queensland"}}],
    )
    assert "2015" in result


def test_parse_ipv6():
    result = bake("2001:0000:4136:e378:8000:63bf:3fff:fdd2", ["Parse IPv6 address"])
    assert "2001:0:4136:e378:8000:63bf:3fff:fdd2" in result


def test_url_encode():
    assert bake("Hello World!", ["URL Encode"]) == "Hello%20World!"


def test_operation_names_and_arg_names_ignore_case_and_spaces():
    assert bake(b"hello", [{"op": "sha2", "args": {"size": "256"}}]) == hashlib.sha256(b"hello").hexdigest()
    assert bake(b"hello", ["toBase64"]) == "aGVsbG8="


def test_positional_args_from_web_app_recipes():
    assert bake("a,b", [{"op": "Split", "args": [",", "\\n"]}]) == "a\nb"


def test_binary_string_args_decode_escapes_like_the_web_app():
    assert bake("a,b", [{"op": "Split", "args": {"Split delimiter": ",", "Join delimiter": "\\t"}}]) == "a\tb"


def test_editable_option_accepts_preset_label():
    assert bake("a b", [{"op": "Split", "args": {"Split delimiter": "Space", "Join delimiter": "Comma"}}]) == "a,b"


def test_unknown_operation_raises():
    with pytest.raises(CyberChefError, match="Couldn't find an operation with name 'Nope'"):
        bake("x", ["Nope"])


def test_operation_error_raises_with_its_message():
    with pytest.raises(CyberChefError, match="all numbers must be between 1 and 26"):
        bake("99", ["A1Z26 Cipher Decode"])


def test_flow_control_runs_in_cyberchef():
    assert bake("a\nb", ["Fork", "To Upper case", "Merge"]) == "A\nB"


def test_bake_simple():
    """Test bake with simple operations."""
    result = bake(b"hello", ["To Base64"])
    assert result == "aGVsbG8="


def test_bake_chain():
    """Test bake with multiple operations."""
    result = bake(b"hello", ["To Base64", "MD5"])
    assert isinstance(result, str)
    assert len(result) == 32


def test_bake_binary():
    """Test bake with binary data that needs to survive encoding."""
    binary_data = bytes(range(256))
    result = bake(binary_data, ["To Hex", "From Hex"])
    assert result == binary_data


def test_bake_with_args():
    """Test bake with operations that have arguments.

    Note: SHA2 size must be string "256", not integer 256.
    """
    result = bake(b"hello", [{"op": "SHA2", "args": {"size": "256"}}])

    # CyberChef's SHA2 should match standard hashlib
    expected = hashlib.sha256(b"hello").hexdigest()
    assert result == expected


def test_bake_sha2_composition():
    """Test SHA2 composition - double hashing works correctly."""
    # Chain two SHA2 operations
    result = bake(
        b"hello",
        [
            {"op": "SHA2", "args": {"size": "256"}},
            {"op": "SHA2", "args": {"size": "256"}},
        ],
    )

    # Expected: SHA256(SHA256("hello"))
    first_hash = hashlib.sha256(b"hello").hexdigest()
    expected = hashlib.sha256(first_hash.encode()).hexdigest()

    assert result == expected
    assert len(result) == 64  # SHA256 produces 64 hex characters


def test_bake_complex_chain():
    """Test bake with a complex chain of operations."""
    result = bake(b"hello", ["To Hex"])
    assert result == "68 65 6c 6c 6f"

    result = bake(result, ["From Hex"])
    assert result == b"hello"

    result = bake(result, ["MD5"])
    expected = "5d41402abc4b2a76b9719d911017c592"
    assert result == expected


def test_bake_hex_to_sha2_chain():
    """Test chaining To Hex followed by SHA2."""
    result = bake(b"hello", [{"op": "To Hex"}, {"op": "SHA2", "args": {"size": "256"}}])

    # Expected: SHA256 of "68 65 6c 6c 6f"
    hex_str = "68 65 6c 6c 6f"
    expected = hashlib.sha256(hex_str.encode()).hexdigest()

    assert result == expected


def test_bake_md5_chain():
    """Test chaining MD5 operations."""
    result = bake(b"hello", [{"op": "MD5"}, {"op": "MD5"}])

    # Expected: MD5(MD5("hello"))
    first_hash = hashlib.md5(b"hello").hexdigest()
    expected = hashlib.md5(first_hash.encode()).hexdigest()

    assert result == expected


def test_bake_url_operations():
    """Test bake with URL encoding operations."""
    result = bake("Hello World!", ["URL Encode"])
    assert result == "Hello%20World!"


def test_bake_empty_recipe():
    """Test bake with empty recipe returns input unchanged."""
    result = bake(b"hello", [])
    assert result == b"hello" or result == "hello"


def test_random_bytes_are_distinct():
    recipe = [{"op": "Pseudo-Random Number Generator", "args": {"Number of bytes": 32, "Output as": "Hex"}}]
    first = bake("", recipe)
    second = bake("", recipe)

    assert len(first) == 64
    assert first != second


def test_bake_generate_uuid_produces_distinct_v4_values():
    first = bake("", ["Generate UUID"])
    second = bake("", ["Generate UUID"])

    first_uuid = uuid.UUID(first)
    second_uuid = uuid.UUID(second)

    assert first_uuid.version == 4
    assert second_uuid.version == 4
    assert first != second
