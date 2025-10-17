import hashlib

from ida_cyberchef.cyberchef import bake, get_chef, plate


def rechef(dish_result, chef):
    """Convert a CyberChef Dish result back to a proper Dish for the next operation.

    This does a double-plate: Dish -> Python type -> Dish
    Needed if Dish objects don't cross the Python/JS boundary cleanly.

    Args:
        dish_result: CyberChef Dish result from previous operation
        chef: CyberChef module instance

    Returns: Fresh Dish instance for next operation
    """
    return plate(plate(dish_result), chef)


def test_from_base64():
    chef = get_chef()
    test_input = "U28gbG9uZyBhbmQgdGhhbmtzIGZvciBhbGwgdGhlIGZpc2gu"
    result = plate(chef.fromBase64(test_input))
    assert result == b"So long and thanks for all the fish."


def test_to_hex():
    chef = get_chef()
    input_dish = plate(b"hello", chef)
    result = plate(chef.toHex(input_dish))
    assert result == "68 65 6c 6c 6f"


def test_md5():
    chef = get_chef()
    input_dish = plate(b"hello", chef)
    result = plate(chef.MD5(input_dish))
    assert result == "5d41402abc4b2a76b9719d911017c592"


def test_chained_operations_with_rechef():
    """Test chaining with rechef() if needed."""
    chef = get_chef()

    input_dish = plate(b"hello", chef)
    step1 = chef.toHex(input_dish)
    step2 = rechef(chef.fromHex(step1), chef)
    step3 = chef.MD5(step2)
    result = plate(step3)

    expected = "5d41402abc4b2a76b9719d911017c592"
    assert result == expected


def test_translate_datetime():
    chef = get_chef()
    result = plate(
        chef.translateDateTimeFormat(
            "15/06/2015 20:45:00", {"outputTimezone": "Australia/Queensland"}
        )
    )
    assert "2015" in result


def test_parse_ipv6():
    chef = get_chef()
    result = plate(chef.parseIPv6Address("2001:0000:4136:e378:8000:63bf:3fff:fdd2"))
    assert "2001:0:4136:e378:8000:63bf:3fff:fdd2" in result


def test_sha256():
    """Test SHA2-256 produces correct standard hash.

    Note: size must be a string "256", not integer 256.
    """

    chef = get_chef()
    input_dish = plate(b"hello", chef)
    result = plate(chef.SHA2(input_dish, {"size": "256"}))
    expected = hashlib.sha256(b"hello").hexdigest()
    assert result == expected


def test_url_encode():
    chef = get_chef()
    result = plate(chef.URLEncode("Hello World!"))
    assert result == "Hello%20World!"


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
