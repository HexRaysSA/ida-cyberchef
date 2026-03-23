"""Tests for OutputKind, TypedOutput, and typed_output_from_value."""

from ida_cyberchef.core.output_model import (
    OutputKind,
    TypedOutput,
    typed_output_from_value,
)


def test_bytes_maps_to_bytes_kind():
    result = typed_output_from_value(b"\x00\x01\x02")
    assert result.kind == OutputKind.BYTES
    assert result.value == b"\x00\x01\x02"


def test_str_maps_to_text_kind():
    result = typed_output_from_value("hello")
    assert result.kind == OutputKind.TEXT
    assert result.value == "hello"


def test_int_maps_to_number_kind():
    result = typed_output_from_value(42)
    assert result.kind == OutputKind.NUMBER
    assert result.value == 42


def test_float_maps_to_number_kind():
    result = typed_output_from_value(3.14)
    assert result.kind == OutputKind.NUMBER
    assert result.value == 3.14


def test_plain_dict_maps_to_json_kind():
    result = typed_output_from_value({"key": "value"})
    assert result.kind == OutputKind.JSON


def test_plain_list_maps_to_json_kind():
    result = typed_output_from_value([1, 2, 3])
    assert result.kind == OutputKind.JSON


def test_cyberchef_file_dict_maps_to_file_kind():
    file_value = {"name": "test.bin", "type": "application/octet-stream", "data": b"\xde\xad"}
    result = typed_output_from_value(file_value)
    assert result.kind == OutputKind.FILE
    assert result.value is file_value


def test_list_of_cyberchef_files_maps_to_file_list_kind():
    files = [
        {"name": "a.bin", "type": "", "data": b"\x00"},
        {"name": "b.bin", "type": "", "data": b"\x01"},
    ]
    result = typed_output_from_value(files)
    assert result.kind == OutputKind.FILE_LIST


def test_empty_list_maps_to_json_kind():
    result = typed_output_from_value([])
    assert result.kind == OutputKind.JSON


def test_mixed_list_maps_to_json_kind():
    result = typed_output_from_value([{"name": "a", "type": "", "data": b""}, 42])
    assert result.kind == OutputKind.JSON


def test_typed_output_dataclass_fields():
    output = TypedOutput(kind=OutputKind.BYTES, value=b"abc")
    assert output.kind == OutputKind.BYTES
    assert output.value == b"abc"
