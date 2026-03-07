"""Generate operation schema from CyberChef runtime introspection."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ida_cyberchef import cyberchef


def extract_js_value(ctx, js_expression):
    """Extract JavaScript value as Python object without double-encoding.

    Args:
        ctx: STPyV8 context
        js_expression: JavaScript expression to evaluate

    Returns: Python value (str, int, float, bool, list, dict, or None)
    """
    js_type = ctx.eval(f"typeof ({js_expression})")

    if js_type in ("string", "number", "boolean"):
        return ctx.eval(js_expression)
    elif js_type == "undefined" or ctx.eval(f"({js_expression}) === null"):
        return None
    else:
        try:
            json_str = ctx.eval(f"JSON.stringify({js_expression})")
            return json.loads(json_str) if json_str else None
        except Exception:
            return None


def extract_operation_metadata(chef, ctx, op_attr_name):
    """Extract metadata for a single operation using runtime introspection.

    Args:
        chef: CyberChef module instance
        ctx: STPyV8 context
        op_attr_name: Operation attribute name (camelCase)

    Returns: Dict with operation metadata or None if extraction fails
    """
    try:
        help_result = chef.help(op_attr_name)

        if not help_result or len(help_result) == 0:
            return None

        ctx.locals.help_result = help_result
        ctx.locals.item_index = 0

        name = ctx.eval("help_result[item_index].name")
        module = ctx.eval("help_result[item_index].module")
        description = ctx.eval("help_result[item_index].description")
        input_type = ctx.eval("help_result[item_index].inputType")
        output_type = ctx.eval("help_result[item_index].outputType")
        info_url = ctx.eval("help_result[item_index].infoURL")
        args_length = ctx.eval(
            "help_result[item_index].args ? help_result[item_index].args.length : 0"
        )

        op_info = {
            "name": name or op_attr_name,
            "module": module or "Unknown",
            "description": description or "",
            "infoURL": info_url or None,
            "inputType": input_type or "string",
            "outputType": output_type or "string",
            "args": [],
        }

        for i in range(args_length):
            ctx.locals.arg_index = i

            arg_name = ctx.eval("help_result[item_index].args[arg_index].name")
            arg_type = ctx.eval("help_result[item_index].args[arg_index].type")
            arg_value = extract_js_value(
                ctx, "help_result[item_index].args[arg_index].value"
            )

            arg_info = {
                "name": arg_name or "",
                "type": arg_type or "string",
                "value": arg_value if arg_value is not None else "",
            }

            has_toggle = ctx.eval(
                "help_result[item_index].args[arg_index].toggleValues !== undefined"
            )
            if has_toggle:
                toggle_values = extract_js_value(
                    ctx, "help_result[item_index].args[arg_index].toggleValues"
                )
                if toggle_values is not None:
                    arg_info["toggleValues"] = toggle_values

            has_default_index = ctx.eval(
                "help_result[item_index].args[arg_index].defaultIndex !== undefined"
            )
            if has_default_index:
                default_index = extract_js_value(
                    ctx, "help_result[item_index].args[arg_index].defaultIndex"
                )
                if default_index is not None:
                    arg_info["defaultIndex"] = default_index

            has_target = ctx.eval(
                "help_result[item_index].args[arg_index].target !== undefined"
            )
            if has_target:
                target = extract_js_value(
                    ctx, "help_result[item_index].args[arg_index].target"
                )
                if target is not None:
                    arg_info["target"] = target

            op_info["args"].append(arg_info)

        return op_info

    except Exception as e:
        print(
            f"Warning: Failed to extract metadata for {op_attr_name}: {e}",
            file=sys.stderr,
        )
        return None


def extract_categories_and_favorites(categories_json_path):
    """Extract category and favorites data from CyberChef Categories.json.

    Args:
        categories_json_path: Path to Categories.json file

    Returns: Dict with 'categories' (operation name -> category) and 'favorites' list
    """
    with open(categories_json_path, "r") as f:
        categories_data = json.load(f)

    categories = {}
    favorites = []

    for category_group in categories_data:
        category_name = category_group.get("name", "")

        if category_name == "Favourites":
            favorites = category_group.get("ops", [])
            continue

        for op_name in category_group.get("ops", []):
            if op_name not in categories:
                categories[op_name] = category_name

    return {"categories": categories, "favorites": favorites}


def enhance_schema_with_categories(schema, categories_json_path):
    """Enhance operation schema with category and favorites data.

    Args:
        schema: Operation schema dict with 'operations' list
        categories_json_path: Path to Categories.json file

    Returns: Enhanced schema with category and is_favorite fields added to each operation
    """
    category_data = extract_categories_and_favorites(categories_json_path)
    categories = category_data["categories"]
    favorites = category_data["favorites"]

    for operation in schema["operations"]:
        op_name = operation.get("name", "")
        operation["category"] = categories.get(op_name, "Other")
        operation["is_favorite"] = op_name in favorites

    return schema


def introspect_operations():
    """Introspect CyberChef operations using runtime API.

    Returns: Dict with operations list
    """
    print("Loading CyberChef...", file=sys.stderr)
    chef = cyberchef.get_chef()
    ctx = chef._stpyv8_context

    print("Discovering operations...", file=sys.stderr)

    excluded_attrs = {
        "bake",
        "help",
        "operations",
        "Dish",
        "DishError",
        "OperationError",
        "ExcludedOperationError",
        "register",
    }

    operation_names = [
        name
        for name in dir(chef)
        if not name.startswith("_") and name not in excluded_attrs
    ]

    print(f"Found {len(operation_names)} operations to introspect", file=sys.stderr)

    operations = []
    failed_count = 0

    for i, op_name in enumerate(operation_names):
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{len(operation_names)}", file=sys.stderr)

        op_info = extract_operation_metadata(chef, ctx, op_name)
        if op_info:
            operations.append(op_info)
        else:
            failed_count += 1

    print(f"\nSuccessfully extracted {len(operations)} operations", file=sys.stderr)
    if failed_count > 0:
        print(f"Failed to extract {failed_count} operations", file=sys.stderr)

    return {"operations": operations}


def main():
    schema = introspect_operations()

    categories_json_path = (
        Path(__file__).parent.parent
        / "deps"
        / "CyberChef"
        / "src"
        / "core"
        / "config"
        / "Categories.json"
    )

    print("\nEnhancing schema with categories and favorites...", file=sys.stderr)
    schema = enhance_schema_with_categories(schema, categories_json_path)

    output_path = (
        Path(__file__).parent.parent
        / "ida_cyberchef"
        / "data"
        / "operation_schema.json"
    )
    with open(output_path, "w") as f:
        json.dump(schema, f, indent=2)

    print(f"\nGenerated schema with {len(schema['operations'])} operations")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
