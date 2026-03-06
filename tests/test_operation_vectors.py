import base64
import hashlib
from dataclasses import dataclass

import pytest

from ida_cyberchef.cyberchef import bake

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class BakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    expected: bytes | str


def build_base58_bitcoin(value: bytes) -> str:
    if not value:
        return ""

    leading_zero_count = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, byteorder="big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    return (BASE58_ALPHABET[0] * leading_zero_count) + encoded


def build_xor_bytes(
    data: bytes,
    key: bytes,
    *,
    null_preserving: bool = False,
) -> bytes:
    result = bytearray()

    for index, value in enumerate(data):
        xored_value = value ^ key[index % len(key)]

        if null_preserving and (value == 0 or xored_value == 0):
            result.append(value)
            continue

        result.append(xored_value)

    return bytes(result)


ENCODING_VECTORS = [
    BakeVector(
        name="to_base64_empty_bytes",
        input_data=b"",
        recipe=["To Base64"],
        expected="",
    ),
    BakeVector(
        name="to_base64_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base64"],
        expected=base64.b64encode(b"hello").decode(),
    ),
    BakeVector(
        name="from_base64_empty_string",
        input_data="",
        recipe=["From Base64"],
        expected=b"",
    ),
    BakeVector(
        name="from_base64_ascii_string",
        input_data="aGVsbG8=",
        recipe=["From Base64"],
        expected=b"hello",
    ),
    BakeVector(
        name="base64_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base64", "From Base64"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base32_empty_bytes",
        input_data=b"",
        recipe=["To Base32"],
        expected="",
    ),
    BakeVector(
        name="to_base32_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Base32"],
        expected=base64.b32encode(b"\x00\x10\x7f\x80\xff").decode(),
    ),
    BakeVector(
        name="from_base32_binary_edge_string",
        input_data="AAIH7AH7",
        recipe=["From Base32"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="base32_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base32", "From Base32"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base58_empty_bytes",
        input_data=b"",
        recipe=["To Base58"],
        expected="",
    ),
    BakeVector(
        name="to_base58_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base58"],
        expected=build_base58_bitcoin(b"hello"),
    ),
    BakeVector(
        name="to_base58_preserves_leading_zero_bytes",
        input_data=b"\x00\x00hello",
        recipe=["To Base58"],
        expected=build_base58_bitcoin(b"\x00\x00hello"),
    ),
    BakeVector(
        name="from_base58_preserves_leading_zero_bytes",
        input_data="11Cn8eVZg",
        recipe=["From Base58"],
        expected=b"\x00\x00hello",
    ),
    BakeVector(
        name="base58_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base58", "From Base58"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_base85_empty_bytes",
        input_data=b"",
        recipe=["To Base85"],
        expected="",
    ),
    BakeVector(
        name="to_base85_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Base85"],
        expected=base64.a85encode(b"\x00\x10\x7f\x80\xff").decode(),
    ),
    BakeVector(
        name="from_base85_binary_edge_string",
        input_data='!"aX1rr',
        recipe=["From Base85"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="base85_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Base85", "From Base85"],
        expected=bytes(range(256)),
    ),
    BakeVector(
        name="to_hex_empty_bytes",
        input_data=b"",
        recipe=["To Hex"],
        expected="",
    ),
    BakeVector(
        name="to_hex_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=["To Hex"],
        expected="00 10 7f 80 ff",
    ),
    BakeVector(
        name="to_hex_no_delimiter_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Hex", "args": {"Delimiter": "None", "Bytes per line": 0}}],
        expected="68656c6c6f",
    ),
    BakeVector(
        name="from_hex_empty_string",
        input_data="",
        recipe=["From Hex"],
        expected=b"",
    ),
    BakeVector(
        name="from_hex_binary_edge_string",
        input_data="00 10 7f 80 ff",
        recipe=["From Hex"],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="from_hex_no_delimiter_string",
        input_data="68656c6c6f",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "None"}}],
        expected=b"hello",
    ),
    BakeVector(
        name="hex_roundtrip_all_byte_values",
        input_data=bytes(range(256)),
        recipe=["To Hex", "From Hex"],
        expected=bytes(range(256)),
    ),
]

HASH_VECTORS = [
    BakeVector(
        name="md5_empty_bytes",
        input_data=b"",
        recipe=["MD5"],
        expected=hashlib.md5(b"").hexdigest(),
    ),
    BakeVector(
        name="md5_ascii_bytes",
        input_data=b"hello",
        recipe=["MD5"],
        expected=hashlib.md5(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha1_ascii_bytes",
        input_data=b"hello",
        recipe=["SHA1"],
        expected=hashlib.sha1(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha2_256_empty_bytes",
        input_data=b"",
        recipe=[{"op": "SHA2", "args": {"size": "256"}}],
        expected=hashlib.sha256(b"").hexdigest(),
    ),
    BakeVector(
        name="sha2_256_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "SHA2", "args": {"size": "256"}}],
        expected=hashlib.sha256(b"hello").hexdigest(),
    ),
    BakeVector(
        name="sha3_256_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "SHA3", "args": {"size": "256"}}],
        expected=hashlib.sha3_256(b"hello").hexdigest(),
    ),
]

TEXT_VECTORS = [
    BakeVector(
        name="url_encode_empty_string",
        input_data="",
        recipe=["URL Encode"],
        expected="",
    ),
    BakeVector(
        name="url_encode_ascii_text",
        input_data="Hello World!",
        recipe=["URL Encode"],
        expected="Hello%20World!",
    ),
    BakeVector(
        name="to_upper_case_all_scope",
        input_data="Hello world!",
        recipe=["To Upper case"],
        expected="HELLO WORLD!",
    ),
    BakeVector(
        name="to_upper_case_word_scope",
        input_data="hello world",
        recipe=[{"op": "To Upper case", "args": {"Scope": "Word"}}],
        expected="Hello World",
    ),
    BakeVector(
        name="to_lower_case_ascii_text",
        input_data="Hello WORLD!",
        recipe=["To Lower case"],
        expected="hello world!",
    ),
]

BINARY_VECTORS = [
    BakeVector(
        name="xor_hex_key_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "ff", "option": "Hex"},
                    "Scheme": "Standard",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"hello", b"\xff"),
    ),
    BakeVector(
        name="xor_utf8_key_without_null_preserving",
        input_data=b"A\x00B",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "A", "option": "UTF8"},
                    "Scheme": "Standard",
                    "Null preserving": False,
                },
            }
        ],
        expected=build_xor_bytes(b"A\x00B", b"A"),
    ),
    BakeVector(
        name="xor_utf8_key_with_null_preserving",
        input_data=b"A\x00B",
        recipe=[
            {
                "op": "XOR",
                "args": {
                    "Key": {"string": "A", "option": "UTF8"},
                    "Scheme": "Standard",
                    "Null preserving": True,
                },
            }
        ],
        expected=build_xor_bytes(b"A\x00B", b"A", null_preserving=True),
    ),
]

BITE_SIZED_BAKE_VECTORS = [
    *ENCODING_VECTORS,
    *HASH_VECTORS,
    *TEXT_VECTORS,
    *BINARY_VECTORS,
]


@pytest.mark.parametrize(
    "vector",
    BITE_SIZED_BAKE_VECTORS,
    ids=[vector.name for vector in BITE_SIZED_BAKE_VECTORS],
)
def test_bake_vectors(vector: BakeVector):
    assert bake(vector.input_data, vector.recipe) == vector.expected
