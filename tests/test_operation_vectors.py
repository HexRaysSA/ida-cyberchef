import base64
import hashlib
import re
from dataclasses import dataclass
from itertools import product

import pytest

from ida_cyberchef.cyberchef import bake

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class BakeVector:
    name: str
    input_data: bytes | str
    recipe: list[str | dict[str, object]]
    expected: bytes | str


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
    *ENCODING_VECTORS,
    *HASH_VECTORS,
    *TEXT_VECTORS,
    *BINARY_VECTORS,
    *ARITHMETIC_LOGIC_VECTORS,
]


@pytest.mark.parametrize(
    "vector",
    BITE_SIZED_BAKE_VECTORS,
    ids=[vector.name for vector in BITE_SIZED_BAKE_VECTORS],
)
def test_bake_vectors(vector: BakeVector):
    assert bake(vector.input_data, vector.recipe) == vector.expected


@pytest.mark.parametrize(
    "vector",
    CODE_TIDY_BLOCKED_VECTORS,
    ids=[vector.name for vector in CODE_TIDY_BLOCKED_VECTORS],
)
def test_bake_vectors_blocked_operations(vector: BlockedBakeVector):
    with pytest.raises(Exception, match=re.escape(vector.error_message)):
        bake(vector.input_data, vector.recipe)
