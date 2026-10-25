"""Generate ida_cyberchef/data/operation_schema.json from CyberChef's config.

Reads OperationConfig.json, which CyberChef's build generates from the
operation sources (`just build` runs that step), and Categories.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parent.parent
CONFIG_DIR = ROOT / "deps" / "CyberChef" / "src" / "core" / "config"
OPERATION_CONFIG_PATH = CONFIG_DIR / "OperationConfig.json"
CATEGORIES_JSON_PATH = CONFIG_DIR / "Categories.json"
OUTPUT_PATH = ROOT / "ida_cyberchef" / "data" / "operation_schema.json"

OperationMetadata = dict[str, Any]


def operation_metadata(name: str, config: dict[str, Any]) -> OperationMetadata:
    """Return the schema entry for one OperationConfig.json entry."""
    args = []
    for raw_arg in config.get("args", []):
        arg: OperationMetadata = {
            "name": raw_arg.get("name") or "",
            "type": raw_arg.get("type") or "string",
            "value": raw_arg.get("value") if raw_arg.get("value") is not None else "",
        }
        for optional_field in ("toggleValues", "defaultIndex", "target"):
            if raw_arg.get(optional_field) is not None:
                arg[optional_field] = raw_arg[optional_field]
        args.append(arg)

    return {
        "name": name,
        "module": config.get("module") or "Unknown",
        "description": config.get("description") or "",
        "infoURL": config.get("infoURL") or None,
        "inputType": config.get("inputType") or "string",
        "outputType": config.get("outputType") or "string",
        "args": args,
    }


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


def main() -> None:
    config = json.loads(OPERATION_CONFIG_PATH.read_text(encoding="utf-8"))
    operations = [operation_metadata(name, config[name]) for name in sorted(config)]
    schema = enhance_schema_with_categories({"operations": operations}, CATEGORIES_JSON_PATH)
    OUTPUT_PATH.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    print(f"Generated schema with {len(operations)} operations")
    print(f"Saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
