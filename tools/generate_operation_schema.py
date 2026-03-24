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


def extract_js_value(ctx: Any, js_expression: str) -> Any:
    """Return a JS value as native Python data."""
    js_type = ctx.eval(f"typeof ({js_expression})")

    if js_type in {"string", "number", "boolean"}:
        return ctx.eval(js_expression)
    if js_type == "undefined" or ctx.eval(f"({js_expression}) === null"):
        return None

    try:
        json_text = ctx.eval(f"JSON.stringify({js_expression})")
    except Exception:
        return None

    return json.loads(json_text) if json_text else None


def extract_operation_metadata(chef: Any, ctx: Any, op_attr_name: str) -> OperationMetadata | None:
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

    ctx.locals.help_result = help_result
    ctx.locals.item_index = 0

    args_length = ctx.eval("help_result[item_index].args ? help_result[item_index].args.length : 0")
    operation: OperationMetadata = {
        "name": ctx.eval("help_result[item_index].name") or op_attr_name,
        "module": ctx.eval("help_result[item_index].module") or "Unknown",
        "description": ctx.eval("help_result[item_index].description") or "",
        "infoURL": ctx.eval("help_result[item_index].infoURL") or None,
        "inputType": ctx.eval("help_result[item_index].inputType") or "string",
        "outputType": ctx.eval("help_result[item_index].outputType") or "string",
        "args": [],
    }

    for index in range(args_length):
        ctx.locals.arg_index = index
        arg: OperationMetadata = {
            "name": ctx.eval("help_result[item_index].args[arg_index].name") or "",
            "type": ctx.eval("help_result[item_index].args[arg_index].type") or "string",
            "value": extract_js_value(ctx, "help_result[item_index].args[arg_index].value") or "",
        }

        if ctx.eval("help_result[item_index].args[arg_index].toggleValues !== undefined"):
            toggle_values = extract_js_value(
                ctx,
                "help_result[item_index].args[arg_index].toggleValues",
            )
            if toggle_values is not None:
                arg["toggleValues"] = toggle_values

        if ctx.eval("help_result[item_index].args[arg_index].defaultIndex !== undefined"):
            default_index = extract_js_value(
                ctx,
                "help_result[item_index].args[arg_index].defaultIndex",
            )
            if default_index is not None:
                arg["defaultIndex"] = default_index

        if ctx.eval("help_result[item_index].args[arg_index].target !== undefined"):
            target = extract_js_value(
                ctx,
                "help_result[item_index].args[arg_index].target",
            )
            if target is not None:
                arg["target"] = target

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
    categories_data = json.loads(categories_json_path.read_text())
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
    ctx = chef._stpyv8_context

    operation_names = [name for name in dir(chef) if not name.startswith("_") and name not in EXCLUDED_ATTRIBUTES]
    print(f"Discovering {len(operation_names)} exported operation attributes...", file=sys.stderr)

    operations: list[OperationMetadata] = []
    failed_count = 0

    for index, op_name in enumerate(operation_names, start=1):
        if index % 50 == 0:
            print(f"  Progress: {index}/{len(operation_names)}", file=sys.stderr)

        operation = extract_operation_metadata(chef, ctx, op_name)
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
