import json
from pathlib import Path

from ida_cyberchef.core.operation_registry import OperationRegistry


def test_operation_schema_exists():
    schema_path = Path("ida_cyberchef/data/operation_schema.json")
    assert schema_path.exists(), (
        "operation_schema.json must exist in ida_cyberchef/data/"
    )


def test_operation_schema_structure():
    with open("ida_cyberchef/data/operation_schema.json", encoding="utf-8") as f:
        schema = json.load(f)

    assert "operations" in schema
    assert isinstance(schema["operations"], list)
    assert len(schema["operations"]) > 0

    op = schema["operations"][0]
    assert "name" in op
    assert "module" in op
    assert "description" in op
    assert "args" in op
    assert isinstance(op["args"], list)


def test_load_operations():
    registry = OperationRegistry()
    ops = registry.get_all_operations()

    assert len(ops) > 0
    assert all("name" in op for op in ops)
    assert all("args" in op for op in ops)


def test_find_operation_by_name():
    registry = OperationRegistry()
    op = registry.find_operation("To Hex")

    assert op is not None
    assert op["name"] == "To Hex"


def test_fuzzy_search_operations():
    registry = OperationRegistry()
    results = registry.search_operations("hex")

    assert len(results) > 0
    assert any("hex" in r["name"].lower() for r in results)
    # Results should be ranked by relevance
    assert results[0]["name"].lower().find("hex") >= 0


def test_acronym_search_operations():
    """Test searching operations by acronyms (e.g., 'b64' for 'Base64').

    Acronym search should match first letters of words separated by spaces or case boundaries.
    """
    registry = OperationRegistry()

    # Test acronyms should work
    results = registry.search_operations("tdd")  # Triple DES Decrypt should match
    assert len(results) > 0
    # Should find operations like "Triple DES"
    triple_des_results = [r for r in results if "Triple DES" in r["name"]]
    assert len(triple_des_results) > 0, (
        "Acronym 'tdd' should match 'Triple DES' or similar"
    )

    # Test "b64" should match "To Base64", "From Base64" etc
    results = registry.search_operations("b64")
    assert len(results) > 0
    base64_results = [r for r in results if "Base64" in r["name"]]
    assert len(base64_results) > 0, "Acronym 'b64' should match Base64 operations"
