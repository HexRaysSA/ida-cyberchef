"""Generate operation schema from CyberChef runtime introspection."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from ida_cyberchef import cyberchef

OperationMetadata = dict[str, Any]


ROOT = Path(__file__).parent.parent
CATEGORIES_JSON_PATH = ROOT / "deps" / "CyberChef" / "src" / "core" / "config" / "Categories.json"
OUTPUT_PATH = ROOT / "ida_cyberchef" / "data" / "operation_schema.json"
EXCLUDED_ATTRIBUTES = {
    "bake",
    "help",
    "operations",
    "Dish",
    "DishError",
    "OperationError",
    "ExcludedOperationError",
    "register",
}


def extract_operation_metadata(chef: Any, op_attr_name: str) -> OperationMetadata | None:
    """Extract metadata for one operation attribute."""
    try:
        help_result = chef.help(op_attr_name)
    except Exception as exc:
        print(
            f"Warning: Failed to extract metadata for {op_attr_name}: {exc}",
            file=sys.stderr,
        )
        return None

    if not help_result or len(help_result) == 0:
        return None

    item = cyberchef.convert_js_json_value(help_result[0])
    if not item:
        return None

    operation: OperationMetadata = {
        "name": item.get("name") or op_attr_name,
        "module": item.get("module") or "Unknown",
        "description": item.get("description") or "",
        "infoURL": item.get("infoURL") or None,
        "inputType": item.get("inputType") or "string",
        "outputType": item.get("outputType") or "string",
        "args": [],
    }

    for raw_arg in item.get("args") or []:
        arg: OperationMetadata = {
            "name": raw_arg.get("name") or "",
            "type": raw_arg.get("type") or "string",
            "value": raw_arg.get("value") if raw_arg.get("value") is not None else "",
        }

        for optional_field in ("toggleValues", "defaultIndex", "target"):
            if raw_arg.get(optional_field) is not None:
                arg[optional_field] = raw_arg[optional_field]

        operation["args"].append(arg)

    return operation


def deduplicate_operations(operations: list[OperationMetadata]) -> list[OperationMetadata]:
    """Return operations deduplicated by user-facing name."""
    deduplicated: list[OperationMetadata] = []
    seen_names: set[str] = set()

    for operation in operations:
        name = str(operation.get("name", ""))
        if name in seen_names:
            print(f"Warning: Skipping duplicate operation metadata for {name}", file=sys.stderr)
            continue
        deduplicated.append(operation)
        seen_names.add(name)

    return deduplicated


def extract_categories_and_favorites(categories_json_path: Path) -> dict[str, Any]:
    """Extract category and favourites data from CyberChef Categories.json."""
    categories_data = json.loads(categories_json_path.read_text(encoding="utf-8"))
    categories: dict[str, str] = {}
    favorites: list[str] = []

    for category_group in categories_data:
        category_name = category_group.get("name", "")

        if category_name == "Favourites":
            favorites = list(category_group.get("ops", []))
            continue

        for op_name in category_group.get("ops", []):
            categories.setdefault(op_name, category_name)

    return {"categories": categories, "favorites": favorites}


def enhance_schema_with_categories(
    schema: dict[str, Any],
    categories_json_path: Path,
) -> dict[str, Any]:
    """Add category and favourite metadata to each operation."""
    category_data = extract_categories_and_favorites(categories_json_path)
    categories = category_data["categories"]
    favorites = set(category_data["favorites"])

    for operation in schema["operations"]:
        op_name = str(operation.get("name", ""))
        operation["category"] = categories.get(op_name, "Other")
        operation["is_favorite"] = op_name in favorites

    return schema


def introspect_operations() -> dict[str, list[OperationMetadata]]:
    """Introspect CyberChef operations through the runtime API."""
    print("Loading CyberChef...", file=sys.stderr)
    chef = cyberchef.get_chef()

    operation_names = [
        name for name in chef.operation_names() if not name.startswith("_") and name not in EXCLUDED_ATTRIBUTES
    ]
    print(f"Discovering {len(operation_names)} exported operation attributes...", file=sys.stderr)

    operations: list[OperationMetadata] = []
    failed_count = 0

    for index, op_name in enumerate(operation_names, start=1):
        if index % 50 == 0:
            print(f"  Progress: {index}/{len(operation_names)}", file=sys.stderr)

        operation = extract_operation_metadata(chef, op_name)
        if operation is None:
            failed_count += 1
            continue
        operations.append(operation)

    operations = deduplicate_operations(operations)
    operations.sort(key=lambda operation: str(operation.get("name", "")))

    print(f"Successfully extracted {len(operations)} unique operations", file=sys.stderr)
    if failed_count:
        print(f"Failed to extract {failed_count} exported attributes", file=sys.stderr)

    return {"operations": operations}


def main() -> None:
    schema = introspect_operations()
    schema = enhance_schema_with_categories(schema, CATEGORIES_JSON_PATH)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2) + "\n")
    print(f"Generated schema with {len(schema['operations'])} operations")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
