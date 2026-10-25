"""Tests for operation schema generation."""

from pathlib import Path

import pytest

from tools.generate_operation_schema import (
    enhance_schema_with_categories,
    extract_categories_and_favorites,
    operation_metadata,
)


def test_extract_categories_and_favorites():
    """Test extracting category and favorites data from Categories.json."""
    categories_json_path = (
        Path(__file__).parent.parent / "deps" / "CyberChef" / "src" / "core" / "config" / "Categories.json"
    )

    if not categories_json_path.exists():
        pytest.skip("CyberChef source tree is not available")

    result = extract_categories_and_favorites(categories_json_path)

    # Should have categories dict mapping operation name to category
    assert "categories" in result
    assert isinstance(result["categories"], dict)

    # Should have favorites list
    assert "favorites" in result
    assert isinstance(result["favorites"], list)

    # Check some known operations have categories
    assert "To Base64" in result["categories"]
    assert result["categories"]["To Base64"] == "Data format"
    assert "AES Decrypt" in result["categories"]
    assert result["categories"]["AES Decrypt"] == "Encryption / Encoding"

    # XOR appears in multiple categories - should pick first
    assert "XOR" in result["categories"]


def test_operation_metadata_keeps_widget_fields():
    config = {
        "module": "Default",
        "description": "Splits a string.",
        "infoURL": "",
        "inputType": "string",
        "outputType": "string",
        "flowControl": False,
        "args": [
            {"name": "Delimiter", "type": "editableOption", "value": [{"name": "Comma", "value": ","}], "hint": "x"},
            {"name": "Count", "type": "number", "value": 1, "min": 0},
        ],
    }

    assert operation_metadata("Split", config) == {
        "name": "Split",
        "module": "Default",
        "description": "Splits a string.",
        "infoURL": None,
        "inputType": "string",
        "outputType": "string",
        "args": [
            {"name": "Delimiter", "type": "editableOption", "value": [{"name": "Comma", "value": ","}]},
            {"name": "Count", "type": "number", "value": 1},
        ],
    }


def test_enhance_schema_with_categories():
    """Test enhancing schema with category and favorites data."""
    categories_json_path = (
        Path(__file__).parent.parent / "deps" / "CyberChef" / "src" / "core" / "config" / "Categories.json"
    )

    schema = {
        "operations": [
            {"name": "To Base64", "module": "Data", "description": "Encode to base64"},
            {
                "name": "To Hex",
                "module": "Data",
                "description": "Encode to hexadecimal",
            },
            {"name": "AES Decrypt", "module": "Crypto", "description": "Decrypt AES"},
        ]
    }

    if not categories_json_path.exists():
        pytest.skip("CyberChef source tree is not available")

    enhanced = enhance_schema_with_categories(schema, categories_json_path)

    # All operations should have category field
    assert all("category" in op for op in enhanced["operations"])
    assert all("is_favorite" in op for op in enhanced["operations"])

    # Check categories are correct
    to_base64 = next(op for op in enhanced["operations"] if op["name"] == "To Base64")
    assert to_base64["category"] == "Data format"

    aes_decrypt = next(op for op in enhanced["operations"] if op["name"] == "AES Decrypt")
    assert aes_decrypt["category"] == "Encryption / Encoding"

    # Unknown operations should have "Other" category
    to_hex = next(op for op in enhanced["operations"] if op["name"] == "To Hex")
    # Since "To Hex" is in the Categories.json, it should have its category
    # But if it wasn't, it would be "Other"
    assert "category" in to_hex
