import base64
import bz2
import calendar
import gzip
import hashlib
import io
import ipaddress
import re
import struct
import tarfile
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import product
from zoneinfo import ZoneInfo

import pytest

from ida_cyberchef.cyberchef import bake

BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)="
BRAILLE_DOT6 = "⠀⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⠚⠛⠜⠝⠞⠟⠠⠡⠢⠣⠤⠥⠦⠧⠨⠩⠪⠫⠬⠭⠮⠯⠰⠱⠲⠳⠴⠵⠶⠷⠸⠹⠺⠻⠼⠽⠾⠿"


@dataclass(frozen=True)
class BakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    expected: object


@dataclass(frozen=True)
class BlockedBakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    error_message: str


EMPTY_BSON_DOCUMENT = b"\x05\x00\x00\x00\x00"
HELLO_WORLD_BSON_DOCUMENT = bytes.fromhex("160000000268656c6c6f0006000000776f726c640000")
MICROSOFT_SCRIPT_SAMPLE_ENCODED = (
    "#@~^RQAAAA==-mD~sX|:/TP{~J:+dYbxL~@!F@*@!+@*@!&@*eEI@#@&@#@&.jm.raY "
    "214Wv:zms/obI0xEAAA==^#~@"
)
MICROSOFT_SCRIPT_SAMPLE_DECODED = 'var my_msg = "Testing <1><2><3>!";\r\n\r\nVScript.Echo(my_msg);'
HELLO_HELLO_HELLO_LZ4_FRAME = bytes.fromhex("04224d184070df0f0000006268656c6c6f2006005068656c6c6f00000000")
HELLO_HELLO_HELLO_LZMA_STREAM = bytes.fromhex(
    "5d00008000110000000000000000341949ee8de94f7f35c5a3ffff78a40000"
)
LZNT1_COMPRESSED_SAMPLE = b"\x1a\xb0\x00compress\x00edtestda\x04ta\x07\x88alot"
HELLO_HELLO_HELLO_RAW_DEFLATE_STREAM = bytes.fromhex("4dc4a109000010c3c0557eb94245a0fbbbd837d7c0ee29")
HELLO_HELLO_HELLO_RAW_DEFLATE_FIXED_STREAM = bytes.fromhex("cb48cdc9c957402201")
HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM = bytes.fromhex(
    "011100eeff68656c6c6f2068656c6c6f2068656c6c6f"
)
HELLO_HELLO_HELLO_ZLIB_STREAM = bytes.fromhex(
    "789c4dc4a109000010c3c0557eb94245a0fbbbd837d7c0ee293a2e067d"
)
HELLO_HELLO_HELLO_ZLIB_FIXED_STREAM = bytes.fromhex("785ecb48cdc9c9574022013a2e067d")
HELLO_HELLO_HELLO_ZLIB_STORE_STREAM = bytes.fromhex(
    "7801011100eeff68656c6c6f2068656c6c6f2068656c6c6f3a2e067d"
)
AMF3_SINGLE_FIELD_OBJECT = b"\x0a\x13\x01\x03a\x06\x09test"
AMF0_SINGLE_FIELD_OBJECT = b"\x03\x00\x01a\x02\x00\x04test\x00\x00\t"
AVRO_SINGLE_RECORD_CONTAINER = (
    b"\x4f\x62\x6a\x01\x04\x16\x61\x76\x72\x6f\x2e\x73\x63\x68\x65\x6d\x61\x96\x01\x7b\x22\x74\x79\x70\x65\x22\x3a\x22\x72\x65"
    b"\x63\x6f\x72\x64\x22\x2c\x22\x6e\x61\x6d\x65\x22\x3a\x22\x73\x6d\x61\x6c\x6c\x22\x2c\x22\x66\x69\x65\x6c\x64\x73\x22\x3a"
    b"\x5b\x7b\x22\x6e\x61\x6d\x65\x22\x3a\x22\x6e\x61\x6d\x65\x22\x2c\x22\x74\x79\x70\x65\x22\x3a\x22\x73\x74\x72\x69\x6e\x67"
    b"\x22\x7d\x5d\x7d\x14\x61\x76\x72\x6f\x2e\x63\x6f\x64\x65\x63\x08\x6e\x75\x6c\x6c\x00\x4e\x02\x47\x63\x2e\x37\x02\xe5\xb7"
    b"\x5c\xda\xb9\xa6\x2f\x15\x41\x02\x0e\x0c\x6d\x79\x6e\x61\x6d\x65\x4e\x02\x47\x63\x2e\x37\x02\xe5\xb7\x5c\xda\xb9\xa6\x2f"
    b"\x15\x41"
)
CSV_COMPLEX_SAMPLE = (
    "A,B,C,D,E,F\r\n"
    "1,2,3,4,5,6\r\n"
    "\",\",;,',\"\"\"\",,\r\n"
    '"""hello""","a""1","multi\r\nline",,,end\r\n'
)
CSV_COMPLEX_ARRAY_OF_DICTS = [
    {"A": "1", "B": "2", "C": "3", "D": "4", "E": "5", "F": "6"},
    {"A": ",", "B": ";", "C": "'", "D": '"', "E": "", "F": ""},
    {"A": '"hello"', "B": 'a"1', "C": "multi\r\nline", "D": "", "E": "", "F": "end"},
]
AMF3_SINGLE_FIELD_OBJECT_DECODED = {
    "marker": 10,
    "$objectTypeIndicator": 19,
    "$traits": {
        "className": {"$lengthOrReference": 1, "$value": ""},
        "sealedMemberNames": [{"$lengthOrReference": 3, "$value": "a"}],
    },
    "_dynamicMembers": [],
    "_values": [{"marker": 6, "stringOrReference": {"$lengthOrReference": 9, "$value": "test"}}],
}
AMF0_SINGLE_FIELD_OBJECT_DECODED = {
    "marker": 3,
    "properties": [{"keyLength": 1, "key": "a", "value": {"marker": 2, "length": 4, "$value": "test"}}],
}
SIMPLE_DER_HEX = "3003020105"
SIMPLE_CERTIFICATE_PEM = "-----BEGIN CERTIFICATE-----\r\nMAMCAQU=\r\n-----END CERTIFICATE-----\r\n"
SIMPLE_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\r\nMAMCAQU=\r\n-----END PUBLIC KEY-----\r\n"
SIMPLE_TLV_HI = bytes.fromhex("01024869")
SIMPLE_LV_SEQUENCE = bytes.fromhex("02486903627965")
SIMPLE_TWO_BYTE_LENGTH_TLV = bytes.fromhex("0102004869")
SIMPLE_BER_TLV = bytes.fromhex("01024142")


def build_base45(value: bytes, alphabet: str = BASE45_ALPHABET) -> str:
    if not value:
        return ""

    encoded = []

    for index in range(0, len(value), 2):
        pair = value[index : index + 2]
        number = 0

        for element in pair:
            number = (number * 256) + element

        chars = 0
        while True:
            encoded.append(alphabet[number % 45])
            chars += 1
            number //= 45
            if number == 0:
                break

        if chars < 2:
            encoded.append("0")
            chars += 1

        if len(pair) > 1 and chars < 3:
            encoded.append("0")

    return "".join(encoded)


def build_expanded_alphabet(pattern: str) -> str:
    expanded = []
    index = 0

    while index < len(pattern):
        character = pattern[index]

        if character == "\\" and index + 1 < len(pattern):
            expanded.append(pattern[index + 1])
            index += 2
            continue

        if index + 2 < len(pattern) and pattern[index + 1] == "-":
            start = ord(character)
            end = ord(pattern[index + 2])
            step = 1 if start <= end else -1
            expanded.extend(chr(code_point) for code_point in range(start, end + step, step))
            index += 3
            continue

        expanded.append(character)
        index += 1

    return "".join(expanded)


def build_base58(value: bytes, alphabet: str = BASE58_ALPHABET) -> str:
    if not value:
        return ""

    leading_zero_count = len(value) - len(value.lstrip(b"\x00"))
    number = int.from_bytes(value, byteorder="big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded

    return (alphabet[0] * leading_zero_count) + encoded


def build_base58_bitcoin(value: bytes) -> str:
    return build_base58(value, BASE58_ALPHABET)


def build_base62(value: bytes, alphabet: str = BASE62_ALPHABET) -> str:
    if not value:
        return ""

    number = int.from_bytes(value, byteorder="big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 62)
        encoded = alphabet[remainder] + encoded

    return encoded or alphabet[0]


def build_base_string(value: int, radix: int) -> str:
    if value == 0:
        return "0"

    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    encoded = ""

    while value:
        value, remainder = divmod(value, radix)
        encoded = digits[remainder] + encoded

    return encoded


def build_base92_character(value: int) -> str:
    if value == 0:
        return "!"

    if value <= 61:
        return chr(ord("#") + value - 1)

    return chr(ord("a") + value - 62)


def build_base92(value: bytes) -> str:
    encoded = []
    bit_string = ""
    remaining = bytes(value)

    while remaining:
        while len(bit_string) < 13 and remaining:
            bit_string += format(remaining[0], "08b")
            remaining = remaining[1:]

        if len(bit_string) < 13:
            break

        number = int(bit_string[:13], 2)
        encoded.append(build_base92_character(number // 91))
        encoded.append(build_base92_character(number % 91))
        bit_string = bit_string[13:]

    if bit_string:
        if len(bit_string) < 7:
            bit_string = bit_string.ljust(6, "0")
            encoded.append(build_base92_character(int(bit_string, 2)))
        else:
            bit_string = bit_string.ljust(13, "0")
            number = int(bit_string[:13], 2)
            encoded.append(build_base92_character(number // 91))
            encoded.append(build_base92_character(number % 91))

    return "".join(encoded)


def build_base64_with_alphabet(value: bytes, alphabet: str) -> str:
    expanded_alphabet = build_expanded_alphabet(alphabet)
    encoded = base64.b64encode(value).decode()
    translated = encoded.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            expanded_alphabet[:64],
        )
    )

    if len(expanded_alphabet) == 64:
        return translated.rstrip("=")

    return translated.replace("=", expanded_alphabet[64])


def get_delimiter_text(name: str) -> str:
    return {
        "Space": " ",
        "Comma": ",",
        "Semi-colon": ";",
        "Colon": ":",
        "Line feed": "\n",
        "CRLF": "\r\n",
        "None": "",
    }[name]


def build_binary_string(value: bytes, delimiter: str, byte_length: int) -> str:
    separator = get_delimiter_text(delimiter)
    return separator.join(format(byte, "b").zfill(byte_length) for byte in value)


def build_braille(value: str) -> str:
    lookup = dict(zip(BRAILLE_ASCII, BRAILLE_DOT6, strict=True))
    return "".join(lookup.get(character.upper(), character) for character in value)


def build_charcode_string(value: str, delimiter: str, base: int) -> str:
    separator = get_delimiter_text(delimiter)
    encoded = []

    for ordinal in map(ord, value):
        if base == 16:
            if ordinal < 256:
                padding = 2
            elif ordinal < 65536:
                padding = 4
            elif ordinal < 16777216:
                padding = 6
            elif ordinal < 4294967296:
                padding = 8
            else:
                padding = 2
            encoded.append(format(ordinal, f"0{padding}x"))
            continue

        encoded.append(build_base_string(ordinal, base))

    return separator.join(encoded)


def build_decimal_string(value: bytes, delimiter: str, *, signed: bool) -> str:
    separator = get_delimiter_text(delimiter)
    if signed:
        numbers = [byte if byte < 128 else byte - 256 for byte in value]
    else:
        numbers = list(value)
    return separator.join(str(number) for number in numbers)


def build_swap_endianness_bytes(
    data: bytes,
    word_length: int,
    *,
    pad_incomplete_words: bool,
) -> bytes:
    swapped = bytearray()

    for index in range(0, len(data), word_length):
        chunk = data[index : index + word_length]

        if len(chunk) < word_length and pad_incomplete_words:
            chunk = chunk.ljust(word_length, b"\x00")

        swapped.extend(reversed(chunk))

    return bytes(swapped)


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


def build_add_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes((value + key[index % len(key)]) % 256 for index, value in enumerate(data))


def build_and_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(0 for _ in data)

    return bytes(value & key[index % len(key)] for index, value in enumerate(data))


def build_or_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes(value | key[index % len(key)] for index, value in enumerate(data))


def build_sub_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data

    return bytes((value - key[index % len(key)]) % 256 for index, value in enumerate(data))


def build_left_shift_bytes(data: bytes, amount: int) -> bytes:
    return bytes((value << amount) & 0xFF for value in data)


def build_right_shift_bytes(data: bytes, amount: int, *, arithmetic: bool) -> bytes:
    result = bytearray()

    for value in data:
        shifted_value = value >> amount
        if arithmetic:
            shifted_value ^= value & 0x80
        result.append(shifted_value)

    return bytes(result)


def build_not_bytes(data: bytes) -> bytes:
    return bytes((~value) & 0xFF for value in data)


def build_rotate_left_bytes(data: bytes, amount: int) -> bytes:
    amount %= 8
    if amount == 0:
        return data

    return bytes(((value << amount) | (value >> (8 - amount))) & 0xFF for value in data)


def build_rotate_right_bytes(data: bytes, amount: int) -> bytes:
    amount %= 8
    if amount == 0:
        return data

    return bytes(((value >> amount) | ((value << (8 - amount)) & 0xFF)) for value in data)


def build_rotate_left_carry_bytes(data: bytes, amount: int) -> bytes:
    if not data:
        return b""

    amount %= 8
    result = [0] * len(data)
    carry_bits = 0

    for index in range(len(data) - 1, -1, -1):
        old_byte = data[index]
        result[index] = ((old_byte << amount) | carry_bits) & 0xFF
        carry_bits = (old_byte >> (8 - amount)) & ((1 << amount) - 1) if amount else 0

    result[-1] |= carry_bits
    return bytes(result)


def build_rotate_right_carry_bytes(data: bytes, amount: int) -> bytes:
    if not data:
        return b""

    amount %= 8
    result = []
    carry_bits = 0

    for old_byte in data:
        result.append((old_byte >> amount) | carry_bits)
        carry_bits = ((old_byte & ((1 << amount) - 1)) << (8 - amount)) if amount else 0

    result[0] |= carry_bits
    return bytes(result)


def build_cartesian_product(samples: list[list[str]], item_delimiter: str) -> str:
    return item_delimiter.join(f"({','.join(items)})" for items in product(*samples))


def build_power_set(items: list[str], item_delimiter: str) -> str:
    filtered_items = [item for item in items if item]
    if not filtered_items:
        return ""

    max_binary_value = int("1" * len(filtered_items), 2)
    subsets = []

    for value in range(max_binary_value + 1):
        binary = format(value, f"0{len(filtered_items)}b")
        subset = item_delimiter.join(
            item for item, bit in zip(filtered_items, binary, strict=True) if bit == "1"
        )
        subsets.append(subset)

    subsets.sort(key=len)
    return "".join(f"{subset}\n" for subset in subsets)


def build_set_difference(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join(item for item in sample_a if item not in sample_b)


def build_set_intersection(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join(item for item in sample_a if item in sample_b)


def build_set_union(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    result = []
    seen = set()

    for item in [*sample_a, *sample_b]:
        if item in seen:
            continue

        seen.add(item)
        result.append(item)

    return item_delimiter.join(result)


def build_symmetric_difference(sample_a: list[str], sample_b: list[str], item_delimiter: str) -> str:
    return item_delimiter.join([
        *[item for item in sample_a if item not in sample_b],
        *[item for item in sample_b if item not in sample_a],
    ])


def build_tar_archive(filename: str, data: bytes) -> bytes:
    buffer = io.BytesIO()

    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(filename)
        info.mode = 0o644
        info.mtime = 0
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    return buffer.getvalue()


def build_zip_archive(
    filename: str,
    data: bytes,
    *,
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, mode="w") as archive:
        info = zipfile.ZipInfo(filename)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = compression
        archive.writestr(info, data)

    return buffer.getvalue()


def build_file_listing(filename: str, data: bytes) -> list[dict[str, object]]:
    return [{"name": filename, "type": "application/unknown", "data": data}]


def build_ordinal_day(day: int) -> str:
    if 10 <= day % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")

    return f"{day}{suffix}"


def build_verbose_utc_datetime(value: datetime) -> str:
    return f"{value.strftime('%a')} {value.day} {value.strftime('%B %Y %H:%M:%S')} UTC"


def build_datetime_delta_string(
    value: str,
    *,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
    seconds: int = 0,
) -> str:
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return (parsed + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def build_from_unix_timestamp_string(value: str, units: str) -> str:
    divisors = {
        "Seconds (s)": 1,
        "Milliseconds (ms)": 1_000,
        "Microseconds (μs)": 1_000_000,
        "Nanoseconds (ns)": 1_000_000_000,
    }
    divisor = divisors[units]
    parsed = datetime.fromtimestamp(int(value) / divisor, tz=timezone.utc)

    if units == "Seconds (s)":
        return build_verbose_utc_datetime(parsed)

    milliseconds = parsed.strftime("%f")[:3]
    return f"{parsed.strftime('%a')} {parsed.day} {parsed.strftime('%B %Y %H:%M:%S')}.{milliseconds} UTC"


def build_parse_datetime_output(value: datetime) -> str:
    return (
        f"Date: {value.strftime('%A')} {build_ordinal_day(value.day)} {value.strftime('%B %Y')}\n"
        f"Time: {value.strftime('%H:%M:%S')}\n"
        f"Period: {value.strftime('%p')}\n"
        f"Timezone: {value.tzname()}\n"
        f"UTC offset: {value.strftime('%z')}\n\n"
        f"Daylight Saving Time: {str(bool(value.dst())).lower()}\n"
        f"Leap year: {str(calendar.isleap(value.year)).lower()}\n"
        f"Days in this month: {calendar.monthrange(value.year, value.month)[1]}\n\n"
        f"Day of year: {value.timetuple().tm_yday}\n"
        f"Week number: {value.isocalendar().week}\n"
        f"Quarter: {((value.month - 1) // 3) + 1}"
    )


def build_to_unix_timestamp_string(value: str, *, units: str, show_parsed_datetime: bool) -> str:
    parsed = datetime.strptime(value, "%a %d %B %Y %H:%M:%S").replace(tzinfo=timezone.utc)
    converters = {
        "Seconds (s)": lambda timestamp: int(timestamp),
        "Milliseconds (ms)": lambda timestamp: int(timestamp * 1_000),
        "Microseconds (μs)": lambda timestamp: int(timestamp * 1_000_000),
        "Nanoseconds (ns)": lambda timestamp: int(timestamp * 1_000_000_000),
    }
    result = converters[units](parsed.timestamp())

    if not show_parsed_datetime:
        return str(result)

    return f"{result} ({build_verbose_utc_datetime(parsed)})"


def build_translated_datetime_output(
    value: str,
    *,
    input_format: str,
    input_timezone: str,
    output_timezone: str,
) -> str:
    parsed = datetime.strptime(value, input_format).replace(tzinfo=ZoneInfo(input_timezone))
    translated = parsed.astimezone(ZoneInfo(output_timezone))
    offset = translated.strftime("%z")
    return (
        f"{translated.strftime('%Y-%m-%d %H:%M:%S')} {offset[:3]}:{offset[3:]}"
        f" {translated.tzname()}"
    )


def build_little_endian_hex(value: int) -> str:
    hex_value = format(value, "x")
    if len(hex_value) % 2:
        hex_value = f"0{hex_value}"
    return "".join(reversed([hex_value[index : index + 2] for index in range(0, len(hex_value), 2)]))


def build_windows_filetime_string(value: str, *, units: str, output_format: str) -> str:
    number = int(value)

    if units == "Seconds (s)":
        intervals = number * 10_000_000
    elif units == "Milliseconds (ms)":
        intervals = number * 10_000
    elif units == "Microseconds (μs)":
        intervals = number * 10
    else:
        intervals = number // 100

    intervals += 116_444_736_000_000_000

    if output_format == "Decimal":
        return str(intervals)

    if output_format == "Hex (big endian)":
        return format(intervals, "x")

    return build_little_endian_hex(intervals)


def build_unix_timestamp_from_windows_filetime_string(
    value: str,
    *,
    output_units: str,
    input_format: str,
) -> str:
    if input_format == "Hex (little endian)":
        chunks = [value[index : index + 2] for index in range(0, len(value), 2)]
        intervals = int("".join(reversed(chunks)), 16)
    elif input_format == "Hex (big endian)":
        intervals = int(value, 16)
    else:
        intervals = int(value)

    unix_intervals = intervals - 116_444_736_000_000_000

    if output_units == "Seconds (s)":
        return str(unix_intervals // 10_000_000)

    if output_units == "Milliseconds (ms)":
        return str(unix_intervals // 10_000)

    if output_units == "Microseconds (μs)":
        return str(unix_intervals // 10)

    return str(unix_intervals * 100)


CODE_TIDY_VECTORS = [
    BakeVector(
        name="bson_serialise_empty_json_object",
        input_data="{}",
        recipe=["BSON serialise"],
        expected=EMPTY_BSON_DOCUMENT,
    ),
    BakeVector(
        name="bson_serialise_string_field_document",
        input_data='{"hello":"world"}',
        recipe=["BSON serialise"],
        expected=HELLO_WORLD_BSON_DOCUMENT,
    ),
    BakeVector(
        name="bson_deserialise_empty_document",
        input_data=EMPTY_BSON_DOCUMENT,
        recipe=["BSON deserialise"],
        expected="{}",
    ),
    BakeVector(
        name="bson_deserialise_string_field_document",
        input_data=HELLO_WORLD_BSON_DOCUMENT,
        recipe=["BSON deserialise"],
        expected='''{
  "hello": "world"
}''',
    ),
    BakeVector(
        name="bson_roundtrip_string_field_document",
        input_data='{"hello":"world"}',
        recipe=["BSON serialise", "BSON deserialise"],
        expected='''{
  "hello": "world"
}''',
    ),
    BakeVector(
        name="css_beautify_empty_string",
        input_data="",
        recipe=["CSS Beautify"],
        expected="",
    ),
    BakeVector(
        name="css_beautify_default_tab_indent",
        input_data="body{color:red;margin:0}",
        recipe=["CSS Beautify"],
        expected="body{\n\\tcolor:red;\n\\tmargin:0\n}\n",
    ),
    BakeVector(
        name="css_beautify_custom_space_indent",
        input_data="body{color:red}",
        recipe=[{"op": "CSS Beautify", "args": {"Indent string": "  "}}],
        expected="body{\n  color:red\n}\n",
    ),
    BakeVector(
        name="css_minify_empty_string",
        input_data="",
        recipe=["CSS Minify"],
        expected="",
    ),
    BakeVector(
        name="css_minify_default_whitespace_reduction",
        input_data="body { color: red; margin: 0; }",
        recipe=["CSS Minify"],
        expected="body {color: red;margin: 0;}",
    ),
    BakeVector(
        name="css_minify_preserve_comments",
        input_data="/*x*/ body { color: red; }",
        recipe=[{"op": "CSS Minify", "args": {"Preserve comments": True}}],
        expected="/*x*/body {color: red;}",
    ),
    BakeVector(
        name="generic_code_beautify_empty_string",
        input_data="",
        recipe=["Generic Code Beautify"],
        expected="",
    ),
    BakeVector(
        name="generic_code_beautify_if_else_block",
        input_data="if(a){b();}else{c();}",
        recipe=["Generic Code Beautify"],
        expected='''if (a)  {
    b();
} else {
    c();
}''',
    ),
    BakeVector(
        name="json_beautify_empty_object",
        input_data="{}",
        recipe=["JSON Beautify"],
        expected="{}",
    ),
    BakeVector(
        name="json_beautify_default_indent",
        input_data='{"b":1,"a":2}',
        recipe=["JSON Beautify"],
        expected='''{
    "b": 1,
    "a": 2
}''',
    ),
    BakeVector(
        name="json_beautify_sort_keys_with_custom_indent",
        input_data='{"b":1,"a":2}',
        recipe=[
            {
                "op": "JSON Beautify",
                "args": {
                    "Indent string": "  ",
                    "Sort Object Keys": True,
                    "Formatted": False,
                },
            }
        ],
        expected='''{
  "a": 2,
  "b": 1
}''',
    ),
    BakeVector(
        name="json_minify_empty_object",
        input_data="{ }",
        recipe=["JSON Minify"],
        expected="{}",
    ),
    BakeVector(
        name="json_minify_compacts_whitespace",
        input_data='''{
  "b": 1,
  "a": 2
}''',
        recipe=["JSON Minify"],
        expected='{"b":1,"a":2}',
    ),
    BakeVector(
        name="json_minify_then_beautify_roundtrip",
        input_data='''{
  "b": 1,
  "a": 2
}''',
        recipe=["JSON Minify", "JSON Beautify"],
        expected='''{
    "b": 1,
    "a": 2
}''',
    ),
    BakeVector(
        name="jq_identity_object",
        input_data='{"a":1,"b":[2,3]}',
        recipe=[{"op": "Jq", "args": {"Query": "."}}],
        expected='{"a":1,"b":[2,3]}',
    ),
    BakeVector(
        name="jq_extract_array_element",
        input_data='{"a":1,"b":[2,3]}',
        recipe=[{"op": "Jq", "args": {"Query": ".b[1]"}}],
        expected="3",
    ),
    BakeVector(
        name="jq_map_then_beautify",
        input_data='[{"a":1},{"a":2}]',
        recipe=[{"op": "Jq", "args": {"Query": "map(.a)"}}, "JSON Beautify"],
        expected='''[
    1,
    2
]''',
    ),
    BakeVector(
        name="microsoft_script_decoder_empty_string",
        input_data="",
        recipe=["Microsoft Script Decoder"],
        expected="",
    ),
    BakeVector(
        name="microsoft_script_decoder_docs_sample",
        input_data=MICROSOFT_SCRIPT_SAMPLE_ENCODED,
        recipe=["Microsoft Script Decoder"],
        expected=MICROSOFT_SCRIPT_SAMPLE_DECODED,
    ),
    BakeVector(
        name="php_deserialize_nested_array_valid_json",
        input_data='a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}',
        recipe=["PHP Deserialize"],
        expected='{"a": 10,"0": {"ab": true}}',
    ),
    BakeVector(
        name="php_deserialize_preserves_numeric_keys_when_not_valid_json",
        input_data='a:2:{s:1:"a";i:10;i:0;a:1:{s:2:"ab";b:1;}}',
        recipe=[{"op": "PHP Deserialize", "args": {"Output valid JSON": False}}],
        expected='{"a": 10,0: {"ab": true}}',
    ),
    BakeVector(
        name="php_serialize_array_docs_example",
        input_data='[5,"abc",true]',
        recipe=["PHP Serialize"],
        expected='a:3:{i:0;i:5;i:1;s:3:"abc";i:2;b:1;}',
    ),
    BakeVector(
        name="php_serialize_then_deserialize_array_roundtrip",
        input_data='[5,"abc",true]',
        recipe=["PHP Serialize", "PHP Deserialize"],
        expected='{"0": 5,"1": "abc","2": true}',
    ),
    BakeVector(
        name="render_markdown_empty_string",
        input_data="",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"></div>',
    ),
    BakeVector(
        name="render_markdown_heading",
        input_data="# hi",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"><h1>hi</h1>\n</div>',
    ),
    BakeVector(
        name="render_markdown_linkify_urls",
        input_data="Visit https://example.com",
        recipe=[
            {
                "op": "Render Markdown",
                "args": {
                    "Autoconvert URLs to links": True,
                    "Enable syntax highlighting": True,
                },
            }
        ],
        expected=(
            '<div style="font-family: var(--primary-font-family)"><p>Visit '
            '<a href="https://example.com">https://example.com</a></p>\n</div>'
        ),
    ),
    BakeVector(
        name="render_markdown_disables_html_rendering",
        input_data="<b>x</b>",
        recipe=["Render Markdown"],
        expected='<div style="font-family: var(--primary-font-family)"><p>&lt;b&gt;x&lt;/b&gt;</p>\n</div>',
    ),
    BakeVector(
        name="sql_beautify_empty_string",
        input_data="",
        recipe=["SQL Beautify"],
        expected="",
    ),
    BakeVector(
        name="sql_beautify_default_layout",
        input_data="select * from users where id=1",
        recipe=["SQL Beautify"],
        expected='''SELECT *
FROM users
WHERE id=1''',
    ),
    BakeVector(
        name="sql_beautify_custom_indent_string",
        input_data='select a, b from users where id=1 and name="x"',
        recipe=[{"op": "SQL Beautify", "args": {"Indent string": "  "}}],
        expected='''SELECT a,
         b
FROM users
WHERE id=1
        AND name="x"''',
    ),
    BakeVector(
        name="sql_minify_empty_string",
        input_data="",
        recipe=["SQL Minify"],
        expected="",
    ),
    BakeVector(
        name="sql_minify_multiline_query",
        input_data='''SELECT a,
       b
FROM users
WHERE id = 1 AND name = "x"''',
        recipe=["SQL Minify"],
        expected='SELECT a, b FROM users WHERE id = 1 AND name = "x"',
    ),
    BakeVector(
        name="sql_minify_then_beautify_roundtrip",
        input_data='''SELECT a,
       b
FROM users
WHERE id = 1 AND name = "x"''',
        recipe=["SQL Minify", "SQL Beautify"],
        expected='''SELECT a,
         b
FROM users
WHERE id = 1
        AND name = "x"''',
    ),
    BakeVector(
        name="strip_html_tags_empty_string",
        input_data="",
        recipe=["Strip HTML tags"],
        expected="",
    ),
    BakeVector(
        name="strip_html_tags_default_cleanup",
        input_data="<div>one</div>\n    <div>two</div>\n\n<div>three</div>",
        recipe=["Strip HTML tags"],
        expected="one\ntwo\nthree",
    ),
    BakeVector(
        name="strip_html_tags_preserve_indentation_and_line_breaks",
        input_data="<div>one</div>\n    <div>two</div>\n\n<div>three</div>",
        recipe=[
            {
                "op": "Strip HTML tags",
                "args": {
                    "Remove indentation": False,
                    "Remove excess line breaks": False,
                },
            }
        ],
        expected="one\n    two\n\nthree",
    ),
    BakeVector(
        name="to_camel_case_empty_string",
        input_data="",
        recipe=["To Camel case"],
        expected="",
    ),
    BakeVector(
        name="to_camel_case_default_transformation",
        input_data="hello_world-test value",
        recipe=["To Camel case"],
        expected="helloWorldTestValue",
    ),
    BakeVector(
        name="to_camel_case_context_aware_variable_names",
        input_data=(
            "const my_variable_name = 1;\n"
            "function another_function_name() { return my_variable_name; }"
        ),
        recipe=[{"op": "To Camel case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
    ),
    BakeVector(
        name="to_kebab_case_empty_string",
        input_data="",
        recipe=["To Kebab case"],
        expected="",
    ),
    BakeVector(
        name="to_kebab_case_default_transformation",
        input_data="hello_world-Test value",
        recipe=["To Kebab case"],
        expected="hello-world-test-value",
    ),
    BakeVector(
        name="to_kebab_case_context_aware_variable_names",
        input_data=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
        recipe=[{"op": "To Kebab case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const my-variable-name = 1;\n"
            "function another-function-name() { return my-variable-name; }"
        ),
    ),
    BakeVector(
        name="to_snake_case_empty_string",
        input_data="",
        recipe=["To Snake case"],
        expected="",
    ),
    BakeVector(
        name="to_snake_case_default_transformation",
        input_data="helloWorld-Test value",
        recipe=["To Snake case"],
        expected="hello_world_test_value",
    ),
    BakeVector(
        name="to_snake_case_context_aware_variable_names",
        input_data=(
            "const myVariableName = 1;\n"
            "function anotherFunctionName() { return myVariableName; }"
        ),
        recipe=[{"op": "To Snake case", "args": {"Attempt to be context aware": True}}],
        expected=(
            "const my_variable_name = 1;\n"
            "function another_function_name() { return my_variable_name; }"
        ),
    ),
    BakeVector(
        name="xml_beautify_empty_string",
        input_data="",
        recipe=["XML Beautify"],
        expected="",
    ),
    BakeVector(
        name="xml_beautify_default_indent_string",
        input_data='<root><item id="1">x</item><item id="2"/></root>',
        recipe=["XML Beautify"],
        expected='''<root>
\\t<item id="1">x</item>
\\t<item id="2"/>
</root>''',
    ),
    BakeVector(
        name="xml_beautify_custom_indent_string",
        input_data="<root><item>1</item></root>",
        recipe=[{"op": "XML Beautify", "args": {"Indent string": "  "}}],
        expected='''<root>
  <item>1</item>
</root>''',
    ),
    BakeVector(
        name="xml_minify_empty_string",
        input_data="",
        recipe=["XML Minify"],
        expected="",
    ),
    BakeVector(
        name="xml_minify_removes_comments_and_whitespace",
        input_data='''<root>
  <!--x-->
  <item id="1">x</item>
</root>''',
        recipe=["XML Minify"],
        expected='<root><item id="1">x</item></root>',
    ),
    BakeVector(
        name="xml_minify_preserves_comments",
        input_data='''<root>
  <!--x-->
  <item id="1">x</item>
</root>''',
        recipe=[{"op": "XML Minify", "args": {"Preserve comments": True}}],
        expected='<root><!--x--><item id="1">x</item></root>',
    ),
    BakeVector(
        name="xml_minify_then_beautify_roundtrip",
        input_data='''<root>
  <item id="1">x</item>
  <item id="2"/>
</root>''',
        recipe=["XML Minify", "XML Beautify"],
        expected='''<root>
\\t<item id="1">x</item>
\\t<item id="2"/>
</root>''',
    ),
]

CODE_TIDY_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="javascript_beautify_excluded_from_node_bundle",
        input_data="const answer=42;",
        recipe=["JavaScript Beautify"],
        error_message=(
            "Sorry, the JavaScriptBeautify operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="javascript_minify_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["JavaScript Minify"],
        error_message=(
            "Sorry, the JavaScriptMinify operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="javascript_parser_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["JavaScript Parser"],
        error_message=(
            "Sorry, the JavaScriptParser operation is not available in the Node.js version of CyberChef."
        ),
    ),
    BlockedBakeVector(
        name="syntax_highlighter_excluded_from_node_bundle",
        input_data="const answer = 42;",
        recipe=["Syntax highlighter"],
        error_message=(
            "Sorry, the SyntaxHighlighter operation is not available in the Node.js version of CyberChef."
        ),
    ),
]

DATA_FORMAT_VECTORS = [
    BakeVector(
        name="amf_encode_amf3_single_string_field_object",
        input_data='{"a":"test"}',
        recipe=[{"op": "AMF Encode", "args": {"Format": "AMF3"}}],
        expected=AMF3_SINGLE_FIELD_OBJECT,
    ),
    BakeVector(
        name="amf_encode_amf0_single_string_field_object",
        input_data='{"a":"test"}',
        recipe=[{"op": "AMF Encode", "args": {"Format": "AMF0"}}],
        expected=AMF0_SINGLE_FIELD_OBJECT,
    ),
    BakeVector(
        name="amf_decode_amf3_single_string_field_object",
        input_data=AMF3_SINGLE_FIELD_OBJECT,
        recipe=[{"op": "AMF Decode", "args": {"Format": "AMF3"}}],
        expected=AMF3_SINGLE_FIELD_OBJECT_DECODED,
    ),
    BakeVector(
        name="amf_decode_amf0_single_string_field_object",
        input_data=AMF0_SINGLE_FIELD_OBJECT,
        recipe=[{"op": "AMF Decode", "args": {"Format": "AMF0"}}],
        expected=AMF0_SINGLE_FIELD_OBJECT_DECODED,
    ),
    BakeVector(
        name="avro_to_json_force_valid_json",
        input_data=AVRO_SINGLE_RECORD_CONTAINER,
        recipe=[{"op": "Avro to JSON", "args": {"Force Valid JSON": True}}],
        expected='''{
    "name": "myname"
}''',
    ),
    BakeVector(
        name="avro_to_json_newline_delimited_json",
        input_data=AVRO_SINGLE_RECORD_CONTAINER,
        recipe=[{"op": "Avro to JSON", "args": {"Force Valid JSON": False}}],
        expected='{"name":"myname"}\n',
    ),
    BakeVector(
        name="cbor_encode_map",
        input_data='{"a":1,"b":2,"c":3}',
        recipe=["CBOR Encode"],
        expected=bytes.fromhex("a3616101616202616303"),
    ),
    BakeVector(
        name="cbor_decode_map",
        input_data=bytes.fromhex("a3616101616202616303"),
        recipe=["CBOR Decode"],
        expected={"a": 1, "b": 2, "c": 3},
    ),
    BakeVector(
        name="cbor_roundtrip_nested_json_value",
        input_data='{"a":1,"b":false,"c":[1,2,3]}',
        recipe=["CBOR Encode", "CBOR Decode"],
        expected={"a": 1, "b": False, "c": [1, 2, 3]},
    ),
    BakeVector(
        name="csv_to_json_array_of_dictionaries",
        input_data=CSV_COMPLEX_SAMPLE,
        recipe=[
            {
                "op": "CSV to JSON",
                "args": {
                    "Cell delimiters": ",",
                    "Row delimiters": "\r\n",
                    "Format": "Array of dictionaries",
                },
            }
        ],
        expected=CSV_COMPLEX_ARRAY_OF_DICTS,
    ),
    BakeVector(
        name="csv_to_json_array_of_arrays_with_custom_delimiters",
        input_data="name;score|alice;10|bob;20",
        recipe=[
            {
                "op": "CSV to JSON",
                "args": {
                    "Cell delimiters": ";",
                    "Row delimiters": "|",
                    "Format": "Array of arrays",
                },
            }
        ],
        expected=[["name", "score"], ["alice", "10"], ["bob", "20"]],
    ),
    BakeVector(
        name="change_ip_format_dotted_decimal_to_hex",
        input_data="192.168.1.1",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Dotted Decimal", "Output format": "Hex"},
            }
        ],
        expected=ipaddress.IPv4Address("192.168.1.1").packed.hex(),
    ),
    BakeVector(
        name="change_ip_format_hex_to_octal",
        input_data="c0a80101",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Hex", "Output format": "Octal"},
            }
        ],
        expected=f"0{int(ipaddress.IPv4Address('192.168.1.1')):o}",
    ),
    BakeVector(
        name="change_ip_format_multiline_decimal_to_dotted_decimal",
        input_data="3232235777\n167772161",
        recipe=[
            {
                "op": "Change IP format",
                "args": {"Input format": "Decimal", "Output format": "Dotted Decimal"},
            }
        ],
        expected="\n".join([
            str(ipaddress.IPv4Address(3232235777)),
            str(ipaddress.IPv4Address(167772161)),
        ]),
    ),
    BakeVector(
        name="decode_text_utf16le_powershell_command",
        input_data=base64.b64decode("ZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA=="),
        recipe=[{"op": "Decode text", "args": {"Encoding": "UTF-16LE (1200)"}}],
        expected='dir "c:\\program files" ',
    ),
    BakeVector(
        name="decode_text_ebcdic_cp500_hello",
        input_data="hello".encode("cp500"),
        recipe=[{"op": "Decode text", "args": {"Encoding": "IBM EBCDIC International (500)"}}],
        expected="hello",
    ),
    BakeVector(
        name="encode_text_utf8_cafe",
        input_data="café",
        recipe=[{"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}}],
        expected="café".encode("utf-8"),
    ),
    BakeVector(
        name="encode_text_ebcdic_cp500_hello",
        input_data="hello",
        recipe=[{"op": "Encode text", "args": {"Encoding": "IBM EBCDIC International (500)"}}],
        expected="hello".encode("cp500"),
    ),
    BakeVector(
        name="encode_decode_text_roundtrip_utf16le",
        input_data="pi ✓",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-16LE (1200)"}},
            {"op": "Decode text", "args": {"Encoding": "UTF-16LE (1200)"}},
        ],
        expected="pi ✓",
    ),
    BakeVector(
        name="escape_unicode_characters_default_greek_text",
        input_data="σου",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "\\u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            }
        ],
        expected="\\u03C3\\u03BF\\u03C5",
    ),
    BakeVector(
        name="escape_unicode_characters_preserve_ascii_with_percent_prefix",
        input_data="Aβ",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "%u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            }
        ],
        expected="A%u03B2",
    ),
    BakeVector(
        name="escape_unicode_characters_encode_all_with_uplus_prefix",
        input_data="A!",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "U+",
                    "Encode all chars": True,
                    "Padding": 6,
                    "Uppercase hex": False,
                },
            }
        ],
        expected="U+000041U+000021",
    ),
    BakeVector(
        name="unescape_unicode_characters_default_greek_text",
        input_data="\\u03C3\\u03BF\\u03C5",
        recipe=["Unescape Unicode Characters"],
        expected="σου",
    ),
    BakeVector(
        name="unescape_unicode_characters_percent_prefix_preserves_ascii",
        input_data="A%u03B2",
        recipe=[{"op": "Unescape Unicode Characters", "args": {"Prefix": "%u"}}],
        expected="Aβ",
    ),
    BakeVector(
        name="unescape_unicode_characters_uplus_prefix_four_digit_units",
        input_data="U+0041U+0021",
        recipe=[{"op": "Unescape Unicode Characters", "args": {"Prefix": "U+"}}],
        expected="A!",
    ),
    BakeVector(
        name="unescape_unicode_characters_surrogate_pair_forms_astral_character",
        input_data="\\uD83D\\uDE00",
        recipe=["Unescape Unicode Characters"],
        expected="😀",
    ),
    BakeVector(
        name="escape_then_unescape_unicode_characters_roundtrip",
        input_data="σου",
        recipe=[
            {
                "op": "Escape Unicode Characters",
                "args": {
                    "Prefix": "\\u",
                    "Encode all chars": False,
                    "Padding": 4,
                    "Uppercase hex": True,
                },
            },
            "Unescape Unicode Characters",
        ],
        expected="σου",
    ),
    BakeVector(
        name="from_bcd_packed_nibbles_1234",
        input_data="0001 0010 0011 0100",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Input format": "Nibbles",
                },
            }
        ],
        expected="1234",
    ),
    BakeVector(
        name="from_bcd_unpacked_bytes_123",
        input_data="00000001 00000010 00000011",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": False,
                    "Signed": False,
                    "Input format": "Bytes",
                },
            }
        ],
        expected="123",
    ),
    BakeVector(
        name="from_bcd_signed_negative_12",
        input_data="0001 0010 1101",
        recipe=[
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": True,
                    "Input format": "Nibbles",
                },
            }
        ],
        expected="-12",
    ),
    BakeVector(
        name="from_base_hex_ff",
        input_data="ff",
        recipe=[{"op": "From Base", "args": {"Radix": 16}}],
        expected=str(int("ff", 16)),
    ),
    BakeVector(
        name="from_base_binary_strips_whitespace",
        input_data="1 0 1 0",
        recipe=[{"op": "From Base", "args": {"Radix": 2}}],
        expected=str(int("1010", 2)),
    ),
    BakeVector(
        name="from_base32_hex_extended_binary_edge_string",
        input_data=base64.b32hexencode(b"\x00\x10\x7f\x80\xff").decode(),
        recipe=[
            {
                "op": "From Base32",
                "args": {"Alphabet": "0-9A-V=", "Remove non-alphabet chars": True},
            }
        ],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="from_base45_ascii_bytes",
        input_data=build_base45(b"AB"),
        recipe=["From Base45"],
        expected=b"AB",
    ),
    BakeVector(
        name="from_base58_ripple_alphabet_ascii_bytes",
        input_data=build_base58(b"hello", BASE58_RIPPLE_ALPHABET),
        recipe=[
            {
                "op": "From Base58",
                "args": {
                    "Alphabet": BASE58_RIPPLE_ALPHABET,
                    "Remove non-alphabet chars": True,
                },
            }
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base62_ascii_bytes",
        input_data=build_base62(b"hello"),
        recipe=["From Base62"],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base62_custom_alphabet_ascii_bytes",
        input_data=build_base62(b"hello", BASE62_ALPHABET[::-1]),
        recipe=[{"op": "From Base62", "args": {"Alphabet": BASE62_ALPHABET[::-1]}}],
        expected=b"hello",
    ),
    BakeVector(
        name="from_base64_urlsafe_binary_edge_string",
        input_data=base64.urlsafe_b64encode(b"\xfb\xef\xff").decode(),
        recipe=[
            {
                "op": "From Base64",
                "args": {
                    "Alphabet": "A-Za-z0-9-_",
                    "Remove non-alphabet chars": True,
                    "Strict mode": False,
                },
            }
        ],
        expected=b"\xfb\xef\xff",
    ),
    BakeVector(
        name="from_base85_custom_zero_group_char",
        input_data="y",
        recipe=[
            {
                "op": "From Base85",
                "args": {
                    "Alphabet": "!-u",
                    "Remove non-alphabet chars": True,
                    "All-zero group char": "y",
                },
            }
        ],
        expected=b"\x00\x00\x00\x00",
    ),
    BakeVector(
        name="from_base92_ascii_bytes",
        input_data=build_base92(b"hello"),
        recipe=["From Base92"],
        expected=b"hello",
    ),
    BakeVector(
        name="from_binary_nibble_groups_without_delimiter",
        input_data="0001001000110100",
        recipe=[{"op": "From Binary", "args": {"Delimiter": "None", "Byte Length": 4}}],
        expected=b"\x01\x02\x03\x04",
    ),
    BakeVector(
        name="from_binary_colon_delimited_bytes",
        input_data="01001000:01101001",
        recipe=[{"op": "From Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_braille_hello_text",
        input_data="⠓⠑⠇⠇⠕",
        recipe=["From Braille"],
        expected="HELLO",
    ),
    BakeVector(
        name="from_braille_preserves_unknown_symbols",
        input_data="⠓⠑?⠇⠕",
        recipe=["From Braille"],
        expected="HE?LO",
    ),
    BakeVector(
        name="from_charcode_base10_comma_ascii",
        input_data="72,101,108,108,111",
        recipe=[{"op": "From Charcode", "args": {"Delimiter": "Comma", "Base": 10}}],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_charcode_concatenated_hex_ascii",
        input_data="48656c6c6f20776f726c64",
        recipe=[{"op": "From Charcode", "args": {"Delimiter": "Space", "Base": 16}}],
        expected=b"Hello world",
    ),
    BakeVector(
        name="from_charcode_roundtrip_colon_hex",
        input_data="Hello",
        recipe=[
            {"op": "To Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
            {"op": "From Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_decimal_colon_delimited_ascii",
        input_data="72:101:108:108:111",
        recipe=[
            {
                "op": "From Decimal",
                "args": {"Delimiter": "Colon", "Support signed values": False},
            }
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="from_decimal_signed_comma_values",
        input_data="-1,-128,127",
        recipe=[
            {
                "op": "From Decimal",
                "args": {"Delimiter": "Comma", "Support signed values": True},
            }
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="from_decimal_roundtrip_signed_values",
        input_data=b"\xff\x80\x7f",
        recipe=[
            {"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
            {"op": "From Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="from_float_big_endian_float_one",
        input_data="1",
        recipe=[
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Big Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Space",
                },
            }
        ],
        expected=struct.pack(">f", 1.0),
    ),
    BakeVector(
        name="from_float_little_endian_double_pair",
        input_data="3.141592653589793,2.5",
        recipe=[
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Double (8 bytes)",
                    "Delimiter": "Comma",
                },
            }
        ],
        expected=struct.pack("<d", 3.141592653589793) + struct.pack("<d", 2.5),
    ),
    BakeVector(
        name="from_float_roundtrip_little_endian_float_values",
        input_data=bytes.fromhex("0000803f000020c0"),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
        ],
        expected=bytes.fromhex("0000803f000020c0"),
    ),
    BakeVector(
        name="from_html_entity_named_numeric_hex_mix",
        input_data="&amp;&lt;&#169;&#x1F600;",
        recipe=["From HTML Entity"],
        expected="&<©😀",
    ),
    BakeVector(
        name="from_html_entity_preserves_unknown_entity",
        input_data="A&bogus;B",
        recipe=["From HTML Entity"],
        expected="A&bogus;B",
    ),
    BakeVector(
        name="from_html_entity_roundtrip_named_entities",
        input_data="5 < 7 & π",
        recipe=[
            {
                "op": "To HTML Entity",
                "args": {
                    "Convert all characters": False,
                    "Convert to": "Named entities",
                },
            },
            "From HTML Entity",
        ],
        expected="5 < 7 & π",
    ),
    BakeVector(
        name="from_hex_percent_delimited_ascii",
        input_data="%48%69",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "Percent"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_hex_0x_with_comma_ascii",
        input_data="0x48,0x69",
        recipe=[{"op": "From Hex", "args": {"Delimiter": "0x with comma"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_hex_content_special_chars",
        input_data="foo|3d|bar",
        recipe=["From Hex Content"],
        expected=b"foo=bar",
    ),
    BakeVector(
        name="from_hex_content_preserves_invalid_segment",
        input_data="foo|zz|bar",
        recipe=["From Hex Content"],
        expected=b"foo|zz|bar",
    ),
    BakeVector(
        name="from_hex_content_roundtrip_with_spaces",
        input_data=b"foo=bar baz",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {
                    "Convert": "Only special chars including spaces",
                    "Print spaces between bytes": True,
                },
            },
            "From Hex Content",
        ],
        expected=b"foo=bar baz",
    ),
    BakeVector(
        name="from_hexdump_classic_multiline",
        input_data=(
            "00000000  68 65 6C 6C 6F 00 77 6F  |hello.wo|\n"
            "00000008  72 6C 64                 |rld|\n"
            "0000000b"
        ),
        recipe=["From Hexdump"],
        expected=b"hello\x00world",
    ),
    BakeVector(
        name="from_hexdump_roundtrip_uppercase_with_final_length",
        input_data=b"hello\x00world",
        recipe=[
            {
                "op": "To Hexdump",
                "args": {
                    "Width": 8,
                    "Upper case hex": True,
                    "Include final length": True,
                    "UNIX format": False,
                },
            },
            "From Hexdump",
        ],
        expected=b"hello\x00world",
    ),
    BakeVector(
        name="from_messagepack_single_map",
        input_data=bytes.fromhex("81a16101"),
        recipe=["From MessagePack"],
        expected={"a": 1},
    ),
    BakeVector(
        name="from_messagepack_roundtrip_nested_value",
        input_data='{"a":1,"b":[true,false]}',
        recipe=["To MessagePack", "From MessagePack"],
        expected={"a": 1, "b": [True, False]},
    ),
    BakeVector(
        name="from_modhex_auto_delimited_ascii",
        input_data="fjhk",
        recipe=["From Modhex"],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_modhex_space_delimited_ascii",
        input_data="fj hk",
        recipe=[{"op": "From Modhex", "args": {"Delimiter": "Space"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_modhex_roundtrip_colon_delimited",
        input_data=b"Hi",
        recipe=[
            {"op": "To Modhex", "args": {"Delimiter": "Colon", "Bytes per line": 0}},
            {"op": "From Modhex", "args": {"Delimiter": "Colon"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_octal_space_delimited_ascii",
        input_data="110 151",
        recipe=[{"op": "From Octal", "args": {"Delimiter": "Space"}}],
        expected=b"Hi",
    ),
    BakeVector(
        name="from_octal_roundtrip_utf8_greek_text",
        input_data="Γειά",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}},
            {"op": "To Octal", "args": {"Delimiter": "Space"}},
            {"op": "From Octal", "args": {"Delimiter": "Space"}},
            {"op": "Decode text", "args": {"Encoding": "UTF-8 (65001)"}},
        ],
        expected="Γειά",
    ),
    BakeVector(
        name="from_punycode_decode_label",
        input_data="mnchen-3ya",
        recipe=["From Punycode"],
        expected="münchen",
    ),
    BakeVector(
        name="from_punycode_decode_idn_domain",
        input_data="xn--mnchen-3ya.de",
        recipe=[{"op": "From Punycode", "args": {"Internationalised domain name": True}}],
        expected="münchen.de",
    ),
    BakeVector(
        name="from_punycode_roundtrip_idn_domain",
        input_data="münchen.de",
        recipe=[
            {"op": "To Punycode", "args": {"Internationalised domain name": True}},
            {"op": "From Punycode", "args": {"Internationalised domain name": True}},
        ],
        expected="münchen.de",
    ),
    BakeVector(
        name="from_quoted_printable_decode_space_escape",
        input_data="hello=20world",
        recipe=["From Quoted Printable"],
        expected=b"hello world",
    ),
    BakeVector(
        name="from_quoted_printable_remove_soft_line_break",
        input_data="soft=\r\nbreak",
        recipe=["From Quoted Printable"],
        expected=b"softbreak",
    ),
    BakeVector(
        name="from_quoted_printable_lowercase_hex_byte",
        input_data="caf=e9",
        recipe=["From Quoted Printable"],
        expected=b"caf\xe9",
    ),
    BakeVector(
        name="hex_to_pem_default_certificate_header",
        input_data=SIMPLE_DER_HEX,
        recipe=["Hex to PEM"],
        expected=SIMPLE_CERTIFICATE_PEM,
    ),
    BakeVector(
        name="hex_to_pem_custom_public_key_header",
        input_data=SIMPLE_DER_HEX,
        recipe=[{"op": "Hex to PEM", "args": {"Header string": "PUBLIC KEY"}}],
        expected=SIMPLE_PUBLIC_KEY_PEM,
    ),
    BakeVector(
        name="json_to_csv_default_row_delimiter_uses_literal_escape_sequence",
        input_data='{"a":1,"b":2}',
        recipe=["JSON to CSV"],
        expected="a,b\\r\\n1,2\\r\\n",
    ),
    BakeVector(
        name="json_to_csv_flattens_nested_object_with_explicit_crlf",
        input_data='{"a":{"b":1},"c":2}',
        recipe=[{"op": "JSON to CSV", "args": {"Cell delimiter": ",", "Row delimiter": "\r\n"}}],
        expected="a.b,c\r\n1,2\r\n",
    ),
    BakeVector(
        name="json_to_csv_custom_delimiters_with_multiline_cell",
        input_data='[[1,2],[3,"a\\nb"]]',
        recipe=[{"op": "JSON to CSV", "args": {"Cell delimiter": ";", "Row delimiter": "|"}}],
        expected='1;2|3;"a\nb"|',
    ),
    BakeVector(
        name="json_to_yaml_nested_object",
        input_data='{"a":1,"b":[2,3]}',
        recipe=["JSON to YAML"],
        expected="a: 1\nb:\n  - 2\n  - 3\n",
    ),
    BakeVector(
        name="json_to_yaml_roundtrip_via_yaml_to_json",
        input_data='{"a":1,"b":[2,3]}',
        recipe=["JSON to YAML", "YAML to JSON"],
        expected={"a": 1, "b": [2, 3]},
    ),
    BakeVector(
        name="yaml_to_json_nested_object",
        input_data="a: 1\nb:\n  - 2\n  - 3\n",
        recipe=["YAML to JSON"],
        expected={"a": 1, "b": [2, 3]},
    ),
    BakeVector(
        name="yaml_to_json_sequence_of_mappings",
        input_data="- name: alice\n  score: 10\n- name: bob\n  score: 20\n",
        recipe=["YAML to JSON"],
        expected=[{"name": "alice", "score": 10}, {"name": "bob", "score": 20}],
    ),
    BakeVector(
        name="yaml_to_json_scalar_boolean",
        input_data="true\n",
        recipe=["YAML to JSON"],
        expected=True,
    ),
    BakeVector(
        name="yaml_to_json_then_json_beautify",
        input_data="a: 1\nb:\n  - 2\n  - 3\n",
        recipe=["YAML to JSON", "JSON Beautify"],
        expected='''{
    "a": 1,
    "b": [
        2,
        3
    ]
}''',
    ),
    BakeVector(
        name="mime_decoding_q_encoded_utf8_header",
        input_data=b"Subject: =?UTF-8?Q?caf=C3=A9?=",
        recipe=["MIME Decoding"],
        expected="Subject: café",
    ),
    BakeVector(
        name="mime_decoding_folded_adjacent_encoded_words",
        input_data=b"Subject: =?UTF-8?Q?caf=C3=A9?=\r\n =?UTF-8?Q?_au_lait?=",
        recipe=["MIME Decoding"],
        expected="Subject: café au lait",
    ),
    BakeVector(
        name="mime_decoding_base64_encoded_word",
        input_data=b"Subject: =?UTF-8?B?Y2Fmw6k=?=",
        recipe=["MIME Decoding"],
        expected="Subject: café",
    ),
    BakeVector(
        name="normalise_unicode_nfd_decomposition",
        input_data="é",
        recipe=[{"op": "Normalise Unicode", "args": {"Normal Form": "NFD"}}],
        expected="é",
    ),
    BakeVector(
        name="normalise_unicode_nfkc_compatibility_digit",
        input_data="①",
        recipe=[{"op": "Normalise Unicode", "args": {"Normal Form": "NFKC"}}],
        expected="1",
    ),
    BakeVector(
        name="normalise_unicode_nfd_then_nfc_roundtrip",
        input_data="é",
        recipe=[
            {"op": "Normalise Unicode", "args": {"Normal Form": "NFD"}},
            {"op": "Normalise Unicode", "args": {"Normal Form": "NFC"}},
        ],
        expected="é",
    ),
    BakeVector(
        name="pem_to_hex_single_certificate_block",
        input_data=SIMPLE_CERTIFICATE_PEM,
        recipe=["PEM to Hex"],
        expected=SIMPLE_DER_HEX,
    ),
    BakeVector(
        name="pem_to_hex_multiple_blocks",
        input_data=SIMPLE_CERTIFICATE_PEM + SIMPLE_PUBLIC_KEY_PEM,
        recipe=["PEM to Hex"],
        expected=f"{SIMPLE_DER_HEX}\n{SIMPLE_DER_HEX}",
    ),
    BakeVector(
        name="pem_to_hex_roundtrip_via_hex_to_pem",
        input_data=SIMPLE_DER_HEX,
        recipe=["Hex to PEM", "PEM to Hex"],
        expected=SIMPLE_DER_HEX,
    ),
    BakeVector(
        name="parse_tlv_simple_tag_length_value",
        input_data=SIMPLE_TLV_HI,
        recipe=["Parse TLV"],
        expected=[{"key": [1], "length": 2, "value": [72, 105]}],
    ),
    BakeVector(
        name="parse_tlv_length_value_sequence_without_key",
        input_data=SIMPLE_LV_SEQUENCE,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 0, "Length size": 1, "Use BER": False}}
        ],
        expected=[
            {"length": 2, "value": [72, 105]},
            {"length": 3, "value": [98, 121, 101]},
        ],
    ),
    BakeVector(
        name="parse_tlv_two_byte_length_field",
        input_data=SIMPLE_TWO_BYTE_LENGTH_TLV,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 1, "Length size": 2, "Use BER": False}}
        ],
        expected=[{"key": [1], "length": 2, "value": [72, 105]}],
    ),
    BakeVector(
        name="parse_tlv_ber_short_form_length",
        input_data=SIMPLE_BER_TLV,
        recipe=[
            {"op": "Parse TLV", "args": {"Type/Key size": 1, "Length size": 1, "Use BER": True}}
        ],
        expected=[{"key": [1], "length": 2, "value": [65, 66]}],
    ),
    BakeVector(
        name="rison_encode_default_nested_object",
        input_data='{"a":1,"b":[true,"x"]}',
        recipe=["Rison Encode"],
        expected="(a:1,b:!(!t,x))",
    ),
    BakeVector(
        name="rison_encode_uri_escapes_reserved_chars",
        input_data='{"a":"a b","b":1}',
        recipe=[{"op": "Rison Encode", "args": {"Encode Option": "Encode URI"}}],
        expected="(a:'a+b',b%3A1)",
    ),
    BakeVector(
        name="rison_decode_object_option",
        input_data="a:1",
        recipe=[{"op": "Rison Decode", "args": {"Decode Option": "Decode Object"}}],
        expected={"a": 1},
    ),
    BakeVector(
        name="rison_decode_array_option",
        input_data="1,x,!f",
        recipe=[{"op": "Rison Decode", "args": {"Decode Option": "Decode Array"}}],
        expected=[1, "x", False],
    ),
    BakeVector(
        name="rison_roundtrip_default_encode_decode",
        input_data='{"a":1,"b":[true,"x"]}',
        recipe=[
            {"op": "Rison Encode", "args": {"Encode Option": "Encode"}},
            {"op": "Rison Decode", "args": {"Decode Option": "Decode"}},
        ],
        expected={"a": 1, "b": [True, "x"]},
    ),
    BakeVector(
        name="show_base64_offsets_plain_offsets_without_variable_chars",
        input_data=b"cat",
        recipe=[
            {
                "op": "Show Base64 offsets",
                "args": {
                    "Alphabet": "A-Za-z0-9+/=",
                    "Show variable chars and padding": False,
                    "Input format": "Raw",
                },
            }
        ],
        expected="Y2F0\nNhd\njYX",
    ),
    BakeVector(
        name="show_base64_offsets_base64_input_matches_raw",
        input_data=b"Y2F0",
        recipe=[
            {
                "op": "Show Base64 offsets",
                "args": {
                    "Alphabet": "A-Za-z0-9+/=",
                    "Show variable chars and padding": False,
                    "Input format": "Base64",
                },
            }
        ],
        expected="Y2F0\nNhd\njYX",
    ),
    BakeVector(
        name="show_base64_offsets_default_html_then_strip_tags",
        input_data=b"cat",
        recipe=["Show Base64 offsets", "Strip HTML tags"],
        expected=(
            "Characters highlighted in green could change if the input is surrounded by more data.\n"
            "Characters highlighted in red are for padding purposes only.\n"
            "Unhighlighted characters are static.\n"
            "Hover over the static sections to see what they decode to on their own.\n"
            "Offset 0: Y2F0\n"
            "Offset 1: AGNhdA==\n"
            "Offset 2: AABjYXQ="
        ),
    ),
    BakeVector(
        name="swap_endianness_hex_default_word_length",
        input_data="0011223344556677",
        recipe=["Swap endianness"],
        expected=build_swap_endianness_bytes(
            bytes.fromhex("0011223344556677"),
            4,
            pad_incomplete_words=True,
        ).hex(" "),
    ),
    BakeVector(
        name="swap_endianness_raw_word_length_four",
        input_data="ABCDEFGH",
        recipe=[
            {
                "op": "Swap endianness",
                "args": {
                    "Data format": "Raw",
                    "Word length (bytes)": 4,
                    "Pad incomplete words": True,
                },
            }
        ],
        expected=build_swap_endianness_bytes(
            b"ABCDEFGH",
            4,
            pad_incomplete_words=True,
        ).decode("latin1"),
    ),
    BakeVector(
        name="swap_endianness_hex_without_padding",
        input_data="0011223344",
        recipe=[
            {
                "op": "Swap endianness",
                "args": {
                    "Data format": "Hex",
                    "Word length (bytes)": 4,
                    "Pad incomplete words": False,
                },
            }
        ],
        expected=build_swap_endianness_bytes(
            bytes.fromhex("0011223344"),
            4,
            pad_incomplete_words=False,
        ).hex(" "),
    ),
    BakeVector(
        name="text_encoding_brute_force_decode_selected_encodings",
        input_data=b"caf\xc3\xa9",
        recipe=[
            {"op": "Text Encoding Brute Force", "args": {"Mode": "Decode"}},
            {
                "op": "Jq",
                "args": {
                    "Query": '{"utf8": .["UTF-8 (65001)"], "cp500": .["IBM EBCDIC International (500)"]}'
                },
            },
        ],
        expected='{"utf8":"café","cp500":"Ä/ÃCz"}',
    ),
    BakeVector(
        name="text_encoding_brute_force_encode_selected_encodings",
        input_data="café",
        recipe=[
            {"op": "Text Encoding Brute Force", "args": {"Mode": "Encode"}},
            {
                "op": "Jq",
                "args": {
                    "Query": '{"utf8": .["UTF-8 (65001)"], "cp500": .["IBM EBCDIC International (500)"]}'
                },
            },
        ],
        expected='{"utf8":"cafÃ©","cp500":"\x83\x81\x86Q"}',
    ),
    BakeVector(
        name="to_bcd_packed_nibbles_1234",
        input_data="1234",
        recipe=["To BCD"],
        expected="0001 0010 0011 0100",
    ),
    BakeVector(
        name="to_bcd_unpacked_bytes_123",
        input_data="123",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": False,
                    "Signed": False,
                    "Output format": "Bytes",
                },
            }
        ],
        expected="00000001 00000010 00000011",
    ),
    BakeVector(
        name="to_bcd_signed_negative_12",
        input_data="-12",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": True,
                    "Output format": "Nibbles",
                },
            }
        ],
        expected="0000 0001 0010 1101",
    ),
    BakeVector(
        name="to_bcd_then_from_bcd_roundtrip",
        input_data="1234",
        recipe=[
            {
                "op": "To BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Output format": "Nibbles",
                },
            },
            {
                "op": "From BCD",
                "args": {
                    "Scheme": "8 4 2 1",
                    "Packed": True,
                    "Signed": False,
                    "Input format": "Nibbles",
                },
            },
        ],
        expected="1234",
    ),
    BakeVector(
        name="to_base_hex_255",
        input_data="255",
        recipe=[{"op": "To Base", "args": {"Radix": 16}}],
        expected=build_base_string(255, 16),
    ),
    BakeVector(
        name="to_base_binary_10",
        input_data="10",
        recipe=[{"op": "To Base", "args": {"Radix": 2}}],
        expected=build_base_string(10, 2),
    ),
    BakeVector(
        name="to_base_roundtrip_via_from_base",
        input_data="255",
        recipe=[
            {"op": "To Base", "args": {"Radix": 16}},
            {"op": "From Base", "args": {"Radix": 16}},
        ],
        expected="255",
    ),
    BakeVector(
        name="to_base32_hex_extended_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base32", "args": {"Alphabet": "0-9A-V="}}],
        expected=base64.b32hexencode(b"hello").decode(),
    ),
    BakeVector(
        name="to_base32_roundtrip_hex_extended_binary_edge_bytes",
        input_data=b"\x00\x10\x7f\x80\xff",
        recipe=[
            {"op": "To Base32", "args": {"Alphabet": "0-9A-V="}},
            {
                "op": "From Base32",
                "args": {"Alphabet": "0-9A-V=", "Remove non-alphabet chars": True},
            },
        ],
        expected=b"\x00\x10\x7f\x80\xff",
    ),
    BakeVector(
        name="to_base45_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base45"],
        expected=build_base45(b"hello"),
    ),
    BakeVector(
        name="to_base45_custom_alphabet_pattern",
        input_data=b"AB",
        recipe=[{"op": "To Base45", "args": {"Alphabet": "A-Z0-9 $%*+\\-./:"}}],
        expected=build_base45(b"AB", build_expanded_alphabet("A-Z0-9 $%*+\\-./:")),
    ),
    BakeVector(
        name="to_base45_roundtrip_ascii_bytes",
        input_data=b"phase 13",
        recipe=["To Base45", "From Base45"],
        expected=b"phase 13",
    ),
    BakeVector(
        name="to_base58_ripple_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base58", "args": {"Alphabet": BASE58_RIPPLE_ALPHABET}}],
        expected=build_base58(b"hello", BASE58_RIPPLE_ALPHABET),
    ),
    BakeVector(
        name="to_base58_ripple_roundtrip_leading_zero_bytes",
        input_data=b"\x00\x00hello",
        recipe=[
            {"op": "To Base58", "args": {"Alphabet": BASE58_RIPPLE_ALPHABET}},
            {
                "op": "From Base58",
                "args": {
                    "Alphabet": BASE58_RIPPLE_ALPHABET,
                    "Remove non-alphabet chars": True,
                },
            },
        ],
        expected=b"\x00\x00hello",
    ),
    BakeVector(
        name="to_base62_ascii_bytes",
        input_data=b"hello",
        recipe=["To Base62"],
        expected=build_base62(b"hello"),
    ),
    BakeVector(
        name="to_base62_custom_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base62", "args": {"Alphabet": "0-9a-zA-Z"}}],
        expected=build_base62(b"hello", build_expanded_alphabet("0-9a-zA-Z")),
    ),
    BakeVector(
        name="to_base62_roundtrip_custom_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {"op": "To Base62", "args": {"Alphabet": "0-9a-zA-Z"}},
            {"op": "From Base62", "args": {"Alphabet": "0-9a-zA-Z"}},
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="to_base64_urlsafe_binary_edge_bytes",
        input_data=b"\xfb\xef\xff",
        recipe=[{"op": "To Base64", "args": {"Alphabet": "A-Za-z0-9-_"}}],
        expected=build_base64_with_alphabet(b"\xfb\xef\xff", "A-Za-z0-9-_"),
    ),
    BakeVector(
        name="to_base64_rot13_alphabet_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base64", "args": {"Alphabet": "N-ZA-Mn-za-m0-9+/="}}],
        expected=build_base64_with_alphabet(b"hello", "N-ZA-Mn-za-m0-9+/="),
    ),
    BakeVector(
        name="to_base64_roundtrip_urlsafe_binary_edge_bytes",
        input_data=b"\xfb\xef\xff",
        recipe=[
            {"op": "To Base64", "args": {"Alphabet": "A-Za-z0-9-_"}},
            {
                "op": "From Base64",
                "args": {
                    "Alphabet": "A-Za-z0-9-_",
                    "Remove non-alphabet chars": True,
                    "Strict mode": False,
                },
            },
        ],
        expected=b"\xfb\xef\xff",
    ),
    BakeVector(
        name="to_base85_zero_group_standard_ascii85",
        input_data=b"\x00\x00\x00\x00",
        recipe=["To Base85"],
        expected="z",
    ),
    BakeVector(
        name="to_base85_include_delimiter_ascii_bytes",
        input_data=b"hello",
        recipe=[{"op": "To Base85", "args": {"Alphabet": "!-u", "Include delimeter": True}}],
        expected=base64.a85encode(b"hello", adobe=True).decode(),
    ),
    BakeVector(
        name="to_base85_roundtrip_with_delimiter_ascii_bytes",
        input_data=b"hello",
        recipe=[
            {"op": "To Base85", "args": {"Alphabet": "!-u", "Include delimeter": True}},
            {
                "op": "From Base85",
                "args": {
                    "Alphabet": "!-u",
                    "Remove non-alphabet chars": True,
                    "All-zero group char": "z",
                },
            },
        ],
        expected=b"hello",
    ),
    BakeVector(
        name="to_base92_empty_string",
        input_data="",
        recipe=["To Base92"],
        expected=b"",
    ),
    BakeVector(
        name="to_base92_ascii_string",
        input_data="hello",
        recipe=["To Base92"],
        expected=build_base92(b"hello").encode(),
    ),
    BakeVector(
        name="to_base92_roundtrip_ascii_string",
        input_data="hello",
        recipe=["To Base92", "From Base92"],
        expected=b"hello",
    ),
    BakeVector(
        name="to_binary_default_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Binary"],
        expected=build_binary_string(b"Hi", "Space", 8),
    ),
    BakeVector(
        name="to_binary_nibble_groups_without_delimiter",
        input_data=b"\x01\x02\x03\x04",
        recipe=[{"op": "To Binary", "args": {"Delimiter": "None", "Byte Length": 4}}],
        expected=build_binary_string(b"\x01\x02\x03\x04", "None", 4),
    ),
    BakeVector(
        name="to_binary_roundtrip_colon_delimited_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}},
            {"op": "From Binary", "args": {"Delimiter": "Colon", "Byte Length": 8}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_braille_hello_text",
        input_data="Hello",
        recipe=["To Braille"],
        expected=build_braille("Hello"),
    ),
    BakeVector(
        name="to_braille_punctuation_text",
        input_data="Hi!",
        recipe=["To Braille"],
        expected=build_braille("Hi!"),
    ),
    BakeVector(
        name="to_braille_roundtrip_ascii_text_uppercases_output",
        input_data="Hello?",
        recipe=["To Braille", "From Braille"],
        expected="HELLO?",
    ),
    BakeVector(
        name="to_charcode_base10_comma_ascii",
        input_data="Hello",
        recipe=[{"op": "To Charcode", "args": {"Delimiter": "Comma", "Base": 10}}],
        expected=build_charcode_string("Hello", "Comma", 10),
    ),
    BakeVector(
        name="to_charcode_hex_greek_text",
        input_data="Γειά σου",
        recipe=["To Charcode"],
        expected=build_charcode_string("Γειά σου", "Space", 16),
    ),
    BakeVector(
        name="to_charcode_roundtrip_colon_hex_ascii",
        input_data="Hello",
        recipe=[
            {"op": "To Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
            {"op": "From Charcode", "args": {"Delimiter": "Colon", "Base": 16}},
        ],
        expected=b"Hello",
    ),
    BakeVector(
        name="to_decimal_default_space_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Decimal"],
        expected=build_decimal_string(b"Hi", "Space", signed=False),
    ),
    BakeVector(
        name="to_decimal_signed_comma_values",
        input_data=b"\xff\x80\x7f",
        recipe=[{"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}}],
        expected=build_decimal_string(b"\xff\x80\x7f", "Comma", signed=True),
    ),
    BakeVector(
        name="to_decimal_roundtrip_signed_values",
        input_data=b"\xff\x80\x7f",
        recipe=[
            {"op": "To Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
            {"op": "From Decimal", "args": {"Delimiter": "Comma", "Support signed values": True}},
        ],
        expected=b"\xff\x80\x7f",
    ),
    BakeVector(
        name="to_float_big_endian_float_one",
        input_data=struct.pack(">f", 1.0),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Big Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Space",
                },
            }
        ],
        expected="1",
    ),
    BakeVector(
        name="to_float_little_endian_double_pair",
        input_data=struct.pack("<d", 3.141592653589793) + struct.pack("<d", 2.5),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Double (8 bytes)",
                    "Delimiter": "Comma",
                },
            }
        ],
        expected="3.141592653589793,2.5",
    ),
    BakeVector(
        name="to_float_roundtrip_little_endian_float_values",
        input_data=bytes.fromhex("0000803f000020c0"),
        recipe=[
            {
                "op": "To Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
            {
                "op": "From Float",
                "args": {
                    "Endianness": "Little Endian",
                    "Size": "Float (4 bytes)",
                    "Delimiter": "Comma",
                },
            },
        ],
        expected=bytes.fromhex("0000803f000020c0"),
    ),
    BakeVector(
        name="to_html_entity_named_entities_with_astral_code_point",
        input_data="&<©😀",
        recipe=["To HTML Entity"],
        expected="&amp;&lt;&copy;&#62976;",
    ),
    BakeVector(
        name="to_html_entity_numeric_entities_for_all_characters",
        input_data="Aβ",
        recipe=[{"op": "To HTML Entity", "args": {"Convert all characters": True, "Convert to": "Numeric entities"}}],
        expected="&#65;&#946;",
    ),
    BakeVector(
        name="to_html_entity_hex_entities_preserve_ascii",
        input_data="&A😀",
        recipe=[{"op": "To HTML Entity", "args": {"Convert all characters": False, "Convert to": "Hex entities"}}],
        expected="&#x26;A&#xf600;",
    ),
    BakeVector(
        name="to_html_entity_roundtrip_named_entities",
        input_data="5 < 7 & π",
        recipe=[
            {
                "op": "To HTML Entity",
                "args": {
                    "Convert all characters": False,
                    "Convert to": "Named entities",
                },
            },
            "From HTML Entity",
        ],
        expected="5 < 7 & π",
    ),
    BakeVector(
        name="to_hex_percent_delimited_ascii_bytes",
        input_data=b"Hi",
        recipe=[{"op": "To Hex", "args": {"Delimiter": "Percent", "Bytes per line": 0}}],
        expected="48%69",
    ),
    BakeVector(
        name="to_hex_percent_roundtrip_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Hex", "args": {"Delimiter": "Percent", "Bytes per line": 0}},
            {"op": "From Hex", "args": {"Delimiter": "Percent"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_hex_content_special_chars_including_spaces",
        input_data=b"foo=bar baz",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {
                    "Convert": "Only special chars including spaces",
                    "Print spaces between bytes": False,
                },
            }
        ],
        expected="foo|3d|bar|20|baz",
    ),
    BakeVector(
        name="to_hex_content_all_chars_with_byte_spacing",
        input_data=b"Hi",
        recipe=[
            {
                "op": "To Hex Content",
                "args": {"Convert": "All chars", "Print spaces between bytes": True},
            }
        ],
        expected="|48 69|",
    ),
    BakeVector(
        name="to_hexdump_empty_bytes",
        input_data=b"",
        recipe=["To Hexdump"],
        expected="",
    ),
    BakeVector(
        name="to_hexdump_multiline_uppercase_with_final_length",
        input_data=b"hello\x00world",
        recipe=[
            {
                "op": "To Hexdump",
                "args": {
                    "Width": 8,
                    "Upper case hex": True,
                    "Include final length": True,
                    "UNIX format": True,
                },
            }
        ],
        expected=(
            "00000000  68 65 6C 6C 6F 00 77 6F  |hello.wo|\n"
            "00000008  72 6C 64                 |rld|\n"
            "0000000b"
        ),
    ),
    BakeVector(
        name="to_messagepack_empty_object",
        input_data="{}",
        recipe=["To MessagePack"],
        expected=b"\x80",
    ),
    BakeVector(
        name="to_messagepack_single_map",
        input_data='{"a":1}',
        recipe=["To MessagePack"],
        expected=bytes.fromhex("81a16101"),
    ),
    BakeVector(
        name="to_modhex_default_ascii_bytes",
        input_data=b"Hi",
        recipe=["To Modhex"],
        expected="fj hk",
    ),
    BakeVector(
        name="to_modhex_custom_colon_delimiter",
        input_data=b"Hi",
        recipe=[{"op": "To Modhex", "args": {"Delimiter": "Colon", "Bytes per line": 0}}],
        expected="fj:hk",
    ),
    BakeVector(
        name="to_octal_colon_delimited_utf8_greek_text",
        input_data="Γειά",
        recipe=[
            {"op": "Encode text", "args": {"Encoding": "UTF-8 (65001)"}},
            {"op": "To Octal", "args": {"Delimiter": "Colon"}},
        ],
        expected="316:223:316:265:316:271:316:254",
    ),
    BakeVector(
        name="to_octal_colon_roundtrip_ascii_bytes",
        input_data=b"Hi",
        recipe=[
            {"op": "To Octal", "args": {"Delimiter": "Colon"}},
            {"op": "From Octal", "args": {"Delimiter": "Colon"}},
        ],
        expected=b"Hi",
    ),
    BakeVector(
        name="to_punycode_label",
        input_data="münchen",
        recipe=["To Punycode"],
        expected="mnchen-3ya",
    ),
    BakeVector(
        name="to_punycode_idn_domain",
        input_data="münchen.de",
        recipe=[{"op": "To Punycode", "args": {"Internationalised domain name": True}}],
        expected="xn--mnchen-3ya.de",
    ),
    BakeVector(
        name="to_quoted_printable_empty_bytes",
        input_data=b"",
        recipe=["To Quoted Printable"],
        expected="",
    ),
    BakeVector(
        name="to_quoted_printable_latin1_bytes",
        input_data=b"caf\xe9",
        recipe=["To Quoted Printable"],
        expected="caf=E9",
    ),
    BakeVector(
        name="to_quoted_printable_wraps_long_lines_with_crlf",
        input_data=b"A" * 80,
        recipe=["To Quoted Printable"],
        expected=("A" * 75) + "=\r\nAAAAA",
    ),
    BakeVector(
        name="to_quoted_printable_roundtrip_binary_bytes",
        input_data=b"hello world=\xff",
        recipe=["To Quoted Printable", "From Quoted Printable"],
        expected=b"hello world=\xff",
    ),
    BakeVector(
        name="url_decode_plus_as_space",
        input_data="a+b%20c",
        recipe=["URL Decode"],
        expected="a b c",
    ),
    BakeVector(
        name="url_decode_preserve_plus",
        input_data="a+b%20c",
        recipe=[{"op": "URL Decode", "args": {"Treat \"+\" as space": False}}],
        expected="a+b c",
    ),
    BakeVector(
        name="url_encode_default_preserves_reserved_uri_chars",
        input_data="a/b?c=d&e=f",
        recipe=["URL Encode"],
        expected="a/b?c=d&e=f",
    ),
    BakeVector(
        name="url_encode_all_special_chars",
        input_data="a+b c=/",
        recipe=[{"op": "URL Encode", "args": {"Encode all special chars": True}}],
        expected="a%2Bb%20c%3D%2F",
    ),
    BakeVector(
        name="url_encode_decode_roundtrip_utf8_text",
        input_data="café",
        recipe=["URL Encode", "URL Decode"],
        expected="café",
    ),
]

COMPRESSION_BLOCKED_VECTORS = [
    BlockedBakeVector(
        name="bzip2_compress_runtime_initialization_hangs",
        input_data=b"hello hello hello",
        recipe=["Bzip2 Compress"],
        error_message="Timed out waiting for CyberChef promise to settle",
    ),
    BlockedBakeVector(
        name="bzip2_decompress_runtime_initialization_hangs",
        input_data=bz2.compress(b"hello hello hello"),
        recipe=["Bzip2 Decompress"],
        error_message="Timed out waiting for CyberChef promise to settle",
    ),
]

COMPRESSION_VECTORS = [
    BakeVector(
        name="gzip_empty_roundtrip",
        input_data=b"",
        recipe=["Gzip", "Gunzip"],
        expected=b"",
    ),
    BakeVector(
        name="gunzip_python_reference_stream",
        input_data=gzip.compress(b"hello hello hello", mtime=0),
        recipe=["Gunzip"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="gzip_fixed_huffman_with_metadata_roundtrip",
        input_data=b"hello hello hello",
        recipe=[
            {
                "op": "Gzip",
                "args": {
                    "Compression type": "Fixed Huffman Coding",
                    "Filename (optional)": "sample.txt",
                    "Comment (optional)": "phase7",
                },
            },
            "Gunzip",
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lz4_compress_empty_bytes",
        input_data=b"",
        recipe=["LZ4 Compress"],
        expected=bytes.fromhex("04224d184070df00000000"),
    ),
    BakeVector(
        name="lz4_compress_repeated_ascii",
        input_data=b"hello hello hello",
        recipe=["LZ4 Compress"],
        expected=HELLO_HELLO_HELLO_LZ4_FRAME,
    ),
    BakeVector(
        name="lz4_decompress_repeated_ascii",
        input_data=HELLO_HELLO_HELLO_LZ4_FRAME,
        recipe=["LZ4 Decompress"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lz4_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["LZ4 Compress", "LZ4 Decompress"],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="lzma_compress_default_mode",
        input_data=b"hello hello hello",
        recipe=["LZMA Compress"],
        expected=HELLO_HELLO_HELLO_LZMA_STREAM,
    ),
    BakeVector(
        name="lzma_decompress_known_size_stream",
        input_data=HELLO_HELLO_HELLO_LZMA_STREAM,
        recipe=["LZMA Decompress"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="lzma_roundtrip_mode_one",
        input_data=bytes(range(64)),
        recipe=[
            {"op": "LZMA Compress", "args": {"Compression Mode": "1"}},
            "LZMA Decompress",
        ],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="lznt1_decompress_empty_bytes",
        input_data=b"",
        recipe=["LZNT1 Decompress"],
        expected=b"",
    ),
    BakeVector(
        name="lznt1_decompress_upstream_reference_sample",
        input_data=LZNT1_COMPRESSED_SAMPLE,
        recipe=["LZNT1 Decompress"],
        expected=b"compressedtestdatacompressedalot",
    ),
    BakeVector(
        name="lzstring_compress_empty_string",
        input_data="",
        recipe=["LZString Compress"],
        expected="䀀",
    ),
    BakeVector(
        name="lzstring_compress_default_format",
        input_data="hello hello hello",
        recipe=["LZString Compress"],
        expected="օ〶惶J፲退",
    ),
    BakeVector(
        name="lzstring_compress_base64_format",
        input_data="hello hello hello",
        recipe=[{"op": "LZString Compress", "args": {"Compression Format": "Base64"}}],
        expected="BYUwNmD2AEoTcpA=",
    ),
    BakeVector(
        name="lzstring_decompress_empty_payload",
        input_data="䀀",
        recipe=["LZString Decompress"],
        expected="",
    ),
    BakeVector(
        name="lzstring_decompress_default_format",
        input_data="օ〶惶J፲退",
        recipe=["LZString Decompress"],
        expected="hello hello hello",
    ),
    BakeVector(
        name="lzstring_decompress_base64_format",
        input_data="BYUwNmD2AEoTcpA=",
        recipe=[{"op": "LZString Decompress", "args": {"Compression Format": "Base64"}}],
        expected="hello hello hello",
    ),
    BakeVector(
        name="lzstring_roundtrip_utf16_format",
        input_data="phase 8 ✓ café",
        recipe=[
            {"op": "LZString Compress", "args": {"Compression Format": "UTF16"}},
            {"op": "LZString Decompress", "args": {"Compression Format": "UTF16"}},
        ],
        expected="phase 8 ✓ café",
    ),
    BakeVector(
        name="raw_deflate_fixed_huffman_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Raw Deflate", "args": {"Compression type": "Fixed Huffman Coding"}}],
        expected=HELLO_HELLO_HELLO_RAW_DEFLATE_FIXED_STREAM,
    ),
    BakeVector(
        name="raw_deflate_none_store_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Raw Deflate", "args": {"Compression type": "None (Store)"}}],
        expected=HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM,
    ),
    BakeVector(
        name="raw_inflate_none_store_ascii",
        input_data=HELLO_HELLO_HELLO_RAW_DEFLATE_STORE_STREAM,
        recipe=["Raw Inflate"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="raw_inflate_start_index_with_block_buffer",
        input_data=b"HEAD" + HELLO_HELLO_HELLO_RAW_DEFLATE_STREAM,
        recipe=[
            {
                "op": "Raw Inflate",
                "args": {
                    "Start index": 4,
                    "Buffer expansion type": "Block",
                    "Resize buffer after decompression": True,
                    "Verify result": True,
                },
            }
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="raw_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["Raw Deflate", "Raw Inflate"],
        expected=bytes(range(64)),
    ),
    BakeVector(
        name="tar_untar_python_reference_archive",
        input_data=build_tar_archive("sample.bin", b"hello hello hello"),
        recipe=["Untar"],
        expected=build_file_listing("sample.bin", b"hello hello hello"),
    ),
    BakeVector(
        name="tar_untar_roundtrip_binary_edge_bytes",
        input_data=bytes(range(32)),
        recipe=[{"op": "Tar", "args": {"Filename": "edge.bin"}}, "Untar"],
        expected=build_file_listing("edge.bin", bytes(range(32))),
    ),
    BakeVector(
        name="unzip_python_reference_stored_archive",
        input_data=build_zip_archive("sample.bin", b"hello hello hello", compression=zipfile.ZIP_STORED),
        recipe=[{"op": "Unzip", "args": {"Verify result": True}}],
        expected=build_file_listing("sample.bin", b"hello hello hello"),
    ),
    BakeVector(
        name="zip_unzip_roundtrip_stored_bytes",
        input_data=bytes(range(32)),
        recipe=[
            {
                "op": "Zip",
                "args": {
                    "Filename": "edge.bin",
                    "Compression method": "None (Store)",
                    "Operating system": "Unix",
                },
            },
            {"op": "Unzip", "args": {"Verify result": True}},
        ],
        expected=build_file_listing("edge.bin", bytes(range(32))),
    ),
    BakeVector(
        name="zlib_deflate_fixed_huffman_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Zlib Deflate", "args": {"Compression type": "Fixed Huffman Coding"}}],
        expected=HELLO_HELLO_HELLO_ZLIB_FIXED_STREAM,
    ),
    BakeVector(
        name="zlib_deflate_none_store_ascii",
        input_data=b"hello hello hello",
        recipe=[{"op": "Zlib Deflate", "args": {"Compression type": "None (Store)"}}],
        expected=HELLO_HELLO_HELLO_ZLIB_STORE_STREAM,
    ),
    BakeVector(
        name="zlib_inflate_none_store_ascii",
        input_data=HELLO_HELLO_HELLO_ZLIB_STORE_STREAM,
        recipe=["Zlib Inflate"],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="zlib_inflate_start_index_with_block_buffer",
        input_data=b"HEAD" + HELLO_HELLO_HELLO_ZLIB_STREAM,
        recipe=[
            {
                "op": "Zlib Inflate",
                "args": {
                    "Start index": 4,
                    "Buffer expansion type": "Block",
                    "Resize buffer after decompression": True,
                    "Verify result": True,
                },
            }
        ],
        expected=b"hello hello hello",
    ),
    BakeVector(
        name="zlib_roundtrip_binary_edge_bytes",
        input_data=bytes(range(64)),
        recipe=["Zlib Deflate", "Zlib Inflate"],
        expected=bytes(range(64)),
    ),
]

DATE_TIME_VECTORS = [
    BakeVector(
        name="datetime_delta_add_across_leap_day_boundary",
        input_data="2024-02-29 23:59:30",
        recipe=[
            {
                "op": "DateTime Delta",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Time Operation": "Add",
                    "Days": 1,
                    "Hours": 0,
                    "Minutes": 1,
                    "Seconds": 45,
                },
            }
        ],
        expected=build_datetime_delta_string(
            "2024-02-29 23:59:30",
            days=1,
            minutes=1,
            seconds=45,
        ),
    ),
    BakeVector(
        name="datetime_delta_subtract_across_previous_day",
        input_data="2024-03-01 00:00:00",
        recipe=[
            {
                "op": "DateTime Delta",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Time Operation": "Subtract",
                    "Days": 1,
                    "Hours": 0,
                    "Minutes": 0,
                    "Seconds": 1,
                },
            }
        ],
        expected=build_datetime_delta_string("2024-03-01 00:00:00", days=-1, seconds=-1),
    ),
    BakeVector(
        name="extract_dates_supported_formats",
        input_data="ignore 2024-02-29 and 03/01/2024 plus 12.31.2025",
        recipe=["Extract dates"],
        expected="2024-02-29\n03/01/2024\n12.31.2025",
    ),
    BakeVector(
        name="extract_dates_display_total",
        input_data="ignore 2024-02-29 and 03/01/2024 plus 12.31.2025",
        recipe=[{"op": "Extract dates", "args": {"Display total": True}}],
        expected="Total found: 3\n\n2024-02-29\n03/01/2024\n12.31.2025",
    ),
    BakeVector(
        name="from_unix_timestamp_seconds_epoch_example",
        input_data="978346800",
        recipe=["From UNIX Timestamp"],
        expected=build_from_unix_timestamp_string("978346800", "Seconds (s)"),
    ),
    BakeVector(
        name="from_unix_timestamp_milliseconds_epoch_example",
        input_data="978346800000",
        recipe=[{"op": "From UNIX Timestamp", "args": {"Units": "Milliseconds (ms)"}}],
        expected=build_from_unix_timestamp_string("978346800000", "Milliseconds (ms)"),
    ),
    BakeVector(
        name="parse_datetime_utc_details",
        input_data="2015-06-15 20:45:00",
        recipe=[
            {
                "op": "Parse DateTime",
                "args": {
                    "Built in formats": "International date and time",
                    "Input format string": "YYYY-MM-DD HH:mm:ss",
                    "Input timezone": "UTC",
                },
            }
        ],
        expected=build_parse_datetime_output(datetime(2015, 6, 15, 20, 45, 0, tzinfo=timezone.utc)),
    ),
    BakeVector(
        name="to_unix_timestamp_seconds_with_parsed_datetime",
        input_data="Mon 1 January 2001 11:00:00",
        recipe=["To UNIX Timestamp"],
        expected=build_to_unix_timestamp_string(
            "Mon 1 January 2001 11:00:00",
            units="Seconds (s)",
            show_parsed_datetime=True,
        ),
    ),
    BakeVector(
        name="to_unix_timestamp_milliseconds_without_parsed_datetime",
        input_data="Mon 1 January 2001 11:00:00",
        recipe=[
            {
                "op": "To UNIX Timestamp",
                "args": {
                    "Units": "Milliseconds (ms)",
                    "Treat as UTC": True,
                    "Show parsed datetime": False,
                },
            }
        ],
        expected=build_to_unix_timestamp_string(
            "Mon 1 January 2001 11:00:00",
            units="Milliseconds (ms)",
            show_parsed_datetime=False,
        ),
    ),
    BakeVector(
        name="translate_datetime_format_utc_to_queensland",
        input_data="15/06/2015 20:45:00",
        recipe=[
            {
                "op": "Translate DateTime Format",
                "args": {
                    "Built in formats": "Standard date and time",
                    "Input format string": "DD/MM/YYYY HH:mm:ss",
                    "Input timezone": "UTC",
                    "Output format string": "YYYY-MM-DD HH:mm:ss Z z",
                    "Output timezone": "Australia/Queensland",
                },
            }
        ],
        expected=build_translated_datetime_output(
            "15/06/2015 20:45:00",
            input_format="%d/%m/%Y %H:%M:%S",
            input_timezone="UTC",
            output_timezone="Australia/Queensland",
        ),
    ),
    BakeVector(
        name="unix_timestamp_to_windows_filetime_decimal_seconds",
        input_data="978346800",
        recipe=["UNIX Timestamp to Windows Filetime"],
        expected=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Decimal",
        ),
    ),
    BakeVector(
        name="unix_timestamp_to_windows_filetime_hex_little_endian",
        input_data="978346800",
        recipe=[
            {
                "op": "UNIX Timestamp to Windows Filetime",
                "args": {
                    "Input units": "Seconds (s)",
                    "Output format": "Hex (little endian)",
                },
            }
        ],
        expected=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Hex (little endian)",
        ),
    ),
    BakeVector(
        name="windows_filetime_to_unix_timestamp_decimal_seconds",
        input_data=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Decimal",
        ),
        recipe=["Windows Filetime to UNIX Timestamp"],
        expected="978346800",
    ),
    BakeVector(
        name="windows_filetime_to_unix_timestamp_hex_little_endian_milliseconds",
        input_data=build_windows_filetime_string(
            "978346800",
            units="Seconds (s)",
            output_format="Hex (little endian)",
        ),
        recipe=[
            {
                "op": "Windows Filetime to UNIX Timestamp",
                "args": {
                    "Output units": "Milliseconds (ms)",
                    "Input format": "Hex (little endian)",
                },
            }
        ],
        expected=build_unix_timestamp_from_windows_filetime_string(
            build_windows_filetime_string(
                "978346800",
                units="Seconds (s)",
                output_format="Hex (little endian)",
            ),
            output_units="Milliseconds (ms)",
            input_format="Hex (little endian)",
        ),
    ),
]

BLOCKED_BAKE_VECTORS = [
    *CODE_TIDY_BLOCKED_VECTORS,
    *COMPRESSION_BLOCKED_VECTORS,
]

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

ARITHMETIC_LOGIC_VECTORS = [
    BakeVector(
        name="add_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "ADD", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="add_wraparound_with_repeating_hex_key",
        input_data=b"\x00\xfe\xff\x10",
        recipe=[
            {
                "op": "ADD",
                "args": {"Key": {"string": "0102", "option": "Hex"}},
            }
        ],
        expected=build_add_bytes(b"\x00\xfe\xff\x10", b"\x01\x02"),
    ),
    BakeVector(
        name="add_utf8_key_option",
        input_data=b"A\xff",
        recipe=[
            {
                "op": "ADD",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_add_bytes(b"A\xff", b"A"),
    ),
    BakeVector(
        name="and_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "AND", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="and_binary_key_option",
        input_data=b"\xff\x0f\xf0",
        recipe=[
            {
                "op": "AND",
                "args": {"Key": {"string": "10100001", "option": "Binary"}},
            }
        ],
        expected=build_and_bytes(b"\xff\x0f\xf0", b"\xa1"),
    ),
    BakeVector(
        name="and_utf8_key_option",
        input_data=b"Az",
        recipe=[
            {
                "op": "AND",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_and_bytes(b"Az", b"A"),
    ),
    BakeVector(
        name="bit_shift_left_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 1}}],
        expected=b"",
    ),
    BakeVector(
        name="bit_shift_left_amount_one",
        input_data=b"\x01\x80\x7f",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 1}}],
        expected=build_left_shift_bytes(b"\x01\x80\x7f", 1),
    ),
    BakeVector(
        name="bit_shift_left_amount_seven",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Bit shift left", "args": {"Amount": 7}}],
        expected=build_left_shift_bytes(b"\x81\x7f", 7),
    ),
    BakeVector(
        name="bit_shift_right_logical",
        input_data=b"\x81\x7f",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 1, "Type": "Logical shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\x81\x7f", 1, arithmetic=False),
    ),
    BakeVector(
        name="bit_shift_right_arithmetic",
        input_data=b"\x81\x7f",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 1, "Type": "Arithmetic shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\x81\x7f", 1, arithmetic=True),
    ),
    BakeVector(
        name="bit_shift_right_amount_two_arithmetic",
        input_data=b"\xff\x40\x20",
        recipe=[
            {
                "op": "Bit shift right",
                "args": {"Amount": 2, "Type": "Arithmetic shift"},
            }
        ],
        expected=build_right_shift_bytes(b"\xff\x40\x20", 2, arithmetic=True),
    ),
    BakeVector(
        name="cartesian_product_two_sets_default_delimiters",
        input_data="red,blue\n\ncircle,square",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_cartesian_product(
            [["red", "blue"], ["circle", "square"]],
            ",",
        ),
    ),
    BakeVector(
        name="cartesian_product_custom_sample_delimiter",
        input_data="a,b|1,2|X,Y",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "|", "Item delimiter": ","},
            }
        ],
        expected=build_cartesian_product(
            [["a", "b"], ["1", "2"], ["X", "Y"]],
            ",",
        ),
    ),
    BakeVector(
        name="cartesian_product_custom_item_delimiter",
        input_data="north/south\n\neast/west",
        recipe=[
            {
                "op": "Cartesian Product",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": "/"},
            }
        ],
        expected=build_cartesian_product(
            [["north", "south"], ["east", "west"]],
            "/",
        ),
    ),
    BakeVector(
        name="divide_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Divide", "args": {"Delimiter": "Space"}}],
        expected="2.5",
    ),
    BakeVector(
        name="divide_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Divide", "args": {"Delimiter": "Space"}}],
        expected="4",
    ),
    BakeVector(
        name="mean_space_delimited_docs_example",
        input_data="0x0a 8 .5 .5",
        recipe=[{"op": "Mean", "args": {"Delimiter": "Space"}}],
        expected="4.75",
    ),
    BakeVector(
        name="mean_comma_delimited_values",
        input_data="1,2,3,4",
        recipe=[{"op": "Mean", "args": {"Delimiter": "Comma"}}],
        expected="2.5",
    ),
    BakeVector(
        name="median_space_delimited_docs_example",
        input_data="0x0a 8 1 .5",
        recipe=[{"op": "Median", "args": {"Delimiter": "Space"}}],
        expected="4.5",
    ),
    BakeVector(
        name="median_sorted_odd_values",
        input_data="1,2,10",
        recipe=[{"op": "Median", "args": {"Delimiter": "Comma"}}],
        expected="2",
    ),
    BakeVector(
        name="multiply_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Multiply", "args": {"Delimiter": "Space"}}],
        expected="40",
    ),
    BakeVector(
        name="multiply_excludes_invalid_tokens",
        input_data="3 nope 2 0.5",
        recipe=[{"op": "Multiply", "args": {"Delimiter": "Space"}}],
        expected="3",
    ),
    BakeVector(
        name="not_empty_bytes",
        input_data=b"",
        recipe=["NOT"],
        expected=b"",
    ),
    BakeVector(
        name="not_binary_edge_bytes",
        input_data=b"\x00\x01\x7f\x80\xff",
        recipe=["NOT"],
        expected=build_not_bytes(b"\x00\x01\x7f\x80\xff"),
    ),
    BakeVector(
        name="not_roundtrip_double_not",
        input_data=bytes(range(32)),
        recipe=["NOT", "NOT"],
        expected=bytes(range(32)),
    ),
    BakeVector(
        name="or_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "OR", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="or_binary_key_option",
        input_data=b"\x0f\xf0U",
        recipe=[
            {
                "op": "OR",
                "args": {"Key": {"string": "10100001", "option": "Binary"}},
            }
        ],
        expected=build_or_bytes(b"\x0f\xf0U", b"\xa1"),
    ),
    BakeVector(
        name="or_utf8_key_option",
        input_data=b"Az",
        recipe=[
            {
                "op": "OR",
                "args": {"Key": {"string": "A", "option": "UTF8"}},
            }
        ],
        expected=build_or_bytes(b"Az", b"A"),
    ),
    BakeVector(
        name="power_set_empty_string",
        input_data="",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": ","}}],
        expected="",
    ),
    BakeVector(
        name="power_set_comma_delimited_values",
        input_data="red,blue",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": ","}}],
        expected=build_power_set(["red", "blue"], ","),
    ),
    BakeVector(
        name="power_set_custom_item_delimiter",
        input_data="north|south",
        recipe=[{"op": "Power Set", "args": {"Item delimiter": "|"}}],
        expected=build_power_set(["north", "south"], "|"),
    ),
    BakeVector(
        name="rotate_left_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Rotate left", "args": {"Amount": 1, "Carry through": False}}],
        expected=b"",
    ),
    BakeVector(
        name="rotate_left_amount_two",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate left", "args": {"Amount": 2, "Carry through": False}}],
        expected=build_rotate_left_bytes(b"\x81\x7f", 2),
    ),
    BakeVector(
        name="rotate_left_carry_through",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate left", "args": {"Amount": 1, "Carry through": True}}],
        expected=build_rotate_left_carry_bytes(b"\x81\x7f", 1),
    ),
    BakeVector(
        name="rotate_right_empty_bytes",
        input_data=b"",
        recipe=[{"op": "Rotate right", "args": {"Amount": 1, "Carry through": False}}],
        expected=b"",
    ),
    BakeVector(
        name="rotate_right_amount_two",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate right", "args": {"Amount": 2, "Carry through": False}}],
        expected=build_rotate_right_bytes(b"\x81\x7f", 2),
    ),
    BakeVector(
        name="rotate_right_carry_through",
        input_data=b"\x81\x7f",
        recipe=[{"op": "Rotate right", "args": {"Amount": 1, "Carry through": True}}],
        expected=build_rotate_right_carry_bytes(b"\x81\x7f", 1),
    ),
    BakeVector(
        name="rotate_roundtrip_left_then_right",
        input_data=bytes(range(32)),
        recipe=[
            {"op": "Rotate left", "args": {"Amount": 3, "Carry through": False}},
            {"op": "Rotate right", "args": {"Amount": 3, "Carry through": False}},
        ],
        expected=bytes(range(32)),
    ),
    BakeVector(
        name="sub_empty_bytes_with_empty_key",
        input_data=b"",
        recipe=[{"op": "SUB", "args": {"Key": {"string": "", "option": "Hex"}}}],
        expected=b"",
    ),
    BakeVector(
        name="sub_wraparound_with_repeating_hex_key",
        input_data=b"\x00\x01\xff\x10",
        recipe=[
            {
                "op": "SUB",
                "args": {"Key": {"string": "0102", "option": "Hex"}},
            }
        ],
        expected=build_sub_bytes(b"\x00\x01\xff\x10", b"\x01\x02"),
    ),
    BakeVector(
        name="sub_base64_key_option",
        input_data=b"A\xff",
        recipe=[
            {
                "op": "SUB",
                "args": {"Key": {"string": "QQ==", "option": "Base64"}},
            }
        ],
        expected=build_sub_bytes(b"A\xff", b"A"),
    ),
    BakeVector(
        name="set_difference_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_difference(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_difference_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Difference",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_difference(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="set_intersection_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Intersection",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_intersection(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_intersection_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Intersection",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_intersection(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="set_union_default_delimiters",
        input_data="red,blue\n\nblue,green",
        recipe=[
            {
                "op": "Set Union",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_set_union(["red", "blue"], ["blue", "green"], ","),
    ),
    BakeVector(
        name="set_union_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Set Union",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_set_union(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="standard_deviation_population_example",
        input_data="2,4,4,4,5,5,7,9",
        recipe=[{"op": "Standard Deviation", "args": {"Delimiter": "Comma"}}],
        expected="2",
    ),
    BakeVector(
        name="standard_deviation_excludes_invalid_tokens",
        input_data="1:3:nope",
        recipe=[{"op": "Standard Deviation", "args": {"Delimiter": "Colon"}}],
        expected="1",
    ),
    BakeVector(
        name="subtract_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Space"}}],
        expected="1.5",
    ),
    BakeVector(
        name="subtract_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Space"}}],
        expected="15",
    ),
    BakeVector(
        name="subtract_comma_delimited_values",
        input_data="10,1,2,3",
        recipe=[{"op": "Subtract", "args": {"Delimiter": "Comma"}}],
        expected="4",
    ),
    BakeVector(
        name="sum_space_delimited_docs_example",
        input_data="0x0a 8 .5",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Space"}}],
        expected="18.5",
    ),
    BakeVector(
        name="sum_excludes_invalid_tokens",
        input_data="20 nope 5",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Space"}}],
        expected="25",
    ),
    BakeVector(
        name="sum_colon_delimited_values",
        input_data="1:2:3:4",
        recipe=[{"op": "Sum", "args": {"Delimiter": "Colon"}}],
        expected="10",
    ),
    BakeVector(
        name="symmetric_difference_default_delimiters",
        input_data="red,blue\n\ngreen,blue",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_symmetric_difference(["red", "blue"], ["green", "blue"], ","),
    ),
    BakeVector(
        name="symmetric_difference_custom_delimiters",
        input_data="north/south|south/east",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "|", "Item delimiter": "/"},
            }
        ],
        expected=build_symmetric_difference(["north", "south"], ["south", "east"], "/"),
    ),
    BakeVector(
        name="symmetric_difference_preserves_duplicates_per_sample_order",
        input_data="red,red,blue\n\ngreen,green,blue",
        recipe=[
            {
                "op": "Symmetric Difference",
                "args": {"Sample delimiter": "\n\n", "Item delimiter": ","},
            }
        ],
        expected=build_symmetric_difference(
            ["red", "red", "blue"],
            ["green", "green", "blue"],
            ",",
        ),
    ),
]

BITE_SIZED_BAKE_VECTORS = [
    *CODE_TIDY_VECTORS,
    *DATA_FORMAT_VECTORS,
    *COMPRESSION_VECTORS,
    *DATE_TIME_VECTORS,
    *ENCODING_VECTORS,
    *HASH_VECTORS,
    *TEXT_VECTORS,
    *BINARY_VECTORS,
    *ARITHMETIC_LOGIC_VECTORS,
]

GET_TIME_GRANULARITIES = [
    ("Seconds (s)", 1_000_000_000, 1),
    ("Milliseconds (ms)", 1_000_000, 1),
    ("Microseconds (μs)", 1_000, 1_000),
    ("Nanoseconds (ns)", 1, 1_000_000),
]


@pytest.mark.parametrize(
    ("granularity", "divisor", "slack"),
    GET_TIME_GRANULARITIES,
    ids=[granularity for granularity, _, _ in GET_TIME_GRANULARITIES],
)
def test_get_time_returns_current_epoch(granularity: str, divisor: int, slack: int):
    lower_bound = time.time_ns() // divisor
    result = bake("", [{"op": "Get Time", "args": {"Granularity": granularity}}])
    upper_bound = time.time_ns() // divisor

    assert lower_bound - slack <= int(result) <= upper_bound + slack


@pytest.mark.parametrize(
    "vector",
    BITE_SIZED_BAKE_VECTORS,
    ids=[vector.name for vector in BITE_SIZED_BAKE_VECTORS],
)
def test_bake_vectors(vector: BakeVector):
    assert bake(vector.input_data, vector.recipe) == vector.expected


@pytest.mark.parametrize(
    "vector",
    BLOCKED_BAKE_VECTORS,
    ids=[vector.name for vector in BLOCKED_BAKE_VECTORS],
)
def test_bake_vectors_blocked_operations(vector: BlockedBakeVector):
    with pytest.raises(Exception, match=re.escape(vector.error_message)):
        bake(vector.input_data, vector.recipe)
