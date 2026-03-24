"""Shared helpers for interpreting CyberChef operation schema data."""

from __future__ import annotations

import json
import warnings
from typing import Any


def _parse_schema_value(value: Any) -> Any:
    """Parse JSON-encoded schema values when needed."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def sanitise_operation_name(value: str) -> str:
    """Return the name form used by CyberChef's name matching."""
    return value.replace(" ", "").lower()


def decode_escaped_string(value: str) -> str:
    """Decode the escape sequences used in CyberChef argument defaults."""
    with warnings.catch_warnings():
        # CyberChef schema defaults use backslash escapes in free-form strings,
        # including regex-style sequences such as "\." and "\-". Python's
        # unicode_escape codec decodes the escapes we need, but can emit
        # warning noise for those literal regex escapes. Preserve the existing
        # decoding behavior while keeping schema normalization quiet.
        warnings.filterwarnings(
            "ignore",
            category=DeprecationWarning,
            message=r"invalid escape sequence",
        )
        warnings.filterwarnings(
            "ignore",
            category=SyntaxWarning,
            message=r"invalid escape sequence",
        )
        return value.encode("raw_unicode_escape").decode("unicode_escape")


def coerce_schema_boolean(value: Any) -> bool:
    """Convert schema boolean values into native booleans."""
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return bool(value)


def get_argument_default_index(arg: dict[str, Any]) -> int:
    """Return the default index for list-like argument values."""
    default_index = arg.get("defaultIndex")
    if isinstance(default_index, int):
        return default_index
    return 0


def _decode_runtime_string(value: Any) -> Any:
    """Decode CyberChef escape sequences for runtime string values."""
    if isinstance(value, str):
        return decode_escaped_string(value)
    return value


def _decode_option_runtime_value(arg_type: str, value: Any) -> Any:
    """Decode option values only for schema types that use escaped runtime strings."""
    if arg_type in {"editableOption", "editableOptionShort"}:
        return _decode_runtime_string(value)
    return value


def _get_option_entries(arg: dict[str, Any]) -> list[dict[str, Any]]:
    """Return normalised option metadata for list-backed schema arguments."""
    raw_value = _parse_schema_value(arg.get("value", ""))
    if not isinstance(raw_value, list):
        return []

    arg_type = str(arg.get("type", "string"))
    options = []
    for entry in raw_value:
        if isinstance(entry, dict):
            label = str(entry.get("name", entry.get("value", "")))
            runtime_value = label if arg_type == "populateMultiOption" else entry.get("value", label)
            options.append(
                {
                    "label": label,
                    "value": _decode_option_runtime_value(arg_type, runtime_value),
                    "raw": entry,
                }
            )
            continue

        options.append(
            {
                "label": str(entry),
                "value": _decode_option_runtime_value(arg_type, entry),
                "raw": entry,
            }
        )

    return options


def get_display_items(arg: dict[str, Any]) -> list[str]:
    """Return the human-readable labels for list-backed arguments."""
    return [option["label"] for option in _get_option_entries(arg)]


def canonicalise_option_value(arg: dict[str, Any], value: Any) -> Any:
    """Resolve display names to the values expected by the runtime."""
    if not isinstance(value, str):
        return value

    for option in _get_option_entries(arg):
        label = option["label"]
        runtime_value = option["value"]

        if sanitise_operation_name(label) == sanitise_operation_name(value):
            return runtime_value
        if isinstance(runtime_value, str) and runtime_value == value:
            return runtime_value

    return value


def get_option_value_for_display(arg: dict[str, Any], display_label: Any) -> Any:
    """Return the runtime value represented by a displayed label."""
    return canonicalise_option_value(arg, display_label)


def get_display_label_for_value(arg: dict[str, Any], value: Any) -> str:
    """Return the display label for a saved runtime value or label."""
    runtime_value = canonicalise_option_value(arg, value)

    for option in _get_option_entries(arg):
        if option["value"] == runtime_value:
            return option["label"]
        if isinstance(value, str) and sanitise_operation_name(option["label"]) == sanitise_operation_name(value):
            return option["label"]

    return "" if value is None else str(value)


def restore_saved_argument_value(arg: dict[str, Any], saved_value: Any) -> Any:
    """Restore saved values using schema-aware canonicalisation rules."""
    arg_type = str(arg.get("type", "string"))

    if arg_type in {"binaryString", "binaryShortString"} and isinstance(saved_value, str):
        return decode_escaped_string(saved_value)

    if arg_type == "boolean":
        return coerce_schema_boolean(saved_value)

    if arg_type == "number" and isinstance(saved_value, str):
        try:
            return int(saved_value) if "." not in saved_value else float(saved_value)
        except ValueError:
            return saved_value

    if arg_type in {
        "argSelector",
        "editableOption",
        "editableOptionShort",
        "option",
        "populateOption",
        "populateMultiOption",
    }:
        return canonicalise_option_value(arg, saved_value)

    return saved_value


def get_argument_default_value(arg: dict[str, Any]) -> Any:
    """Return the normalised default value for a schema argument."""
    arg_type = str(arg.get("type", "string"))
    raw_value = _parse_schema_value(arg.get("value", ""))
    options = _get_option_entries(arg)

    if arg_type in {"binaryString", "binaryShortString"}:
        return _decode_runtime_string(raw_value)

    if arg_type == "boolean":
        return coerce_schema_boolean(raw_value)

    if arg_type == "number":
        if isinstance(raw_value, str):
            try:
                return int(raw_value) if "." not in raw_value else float(raw_value)
            except ValueError:
                return raw_value
        return raw_value

    if arg_type in {
        "argSelector",
        "editableOption",
        "editableOptionShort",
        "option",
        "populateOption",
        "populateMultiOption",
    }:
        if options:
            default_index = min(get_argument_default_index(arg), len(options) - 1)
            return options[default_index]["value"]
        return raw_value

    if arg_type == "toggleString":
        toggle_values = get_toggle_values(arg)
        default_option = toggle_values[0] if toggle_values else ""
        if isinstance(raw_value, dict):
            return {
                "string": str(raw_value.get("string", "")),
                "option": str(raw_value.get("option", default_option)),
            }
        return {
            "string": _decode_runtime_string(raw_value) if raw_value else "",
            "option": default_option,
        }

    return raw_value


def get_toggle_values(arg: dict[str, Any]) -> tuple[str, ...]:
    """Return the available toggleString formats."""
    raw_values = _parse_schema_value(arg.get("toggleValues", []))
    if not isinstance(raw_values, list):
        return ()
    return tuple(str(value) for value in raw_values)


def expand_populate_multi_option(arg: dict[str, Any], value: Any) -> dict[str, Any]:
    """Expand populateMultiOption selections into their target arguments."""
    if not isinstance(value, str):
        return {}

    targets = arg.get("target")
    if not isinstance(targets, list):
        return {}

    selected_value = canonicalise_option_value(arg, value)
    for option in _get_option_entries(arg):
        if option["value"] != selected_value:
            continue

        raw_option = option["raw"]
        if not isinstance(raw_option, dict):
            return {}

        expanded_values = raw_option.get("value", [])
        if not isinstance(expanded_values, list):
            return {}
        return {
            str(target_index): expanded_values[index]
            for index, target_index in enumerate(targets)
            if index < len(expanded_values)
        }

    return {}


def get_dependent_args(
    operation_args: list[dict[str, Any]],
    selector_arg: dict[str, Any],
    selected_value: Any,
) -> tuple[set[str], set[str]]:
    """Return argSelector-driven visible and hidden argument names."""
    selected_label = get_display_label_for_value(selector_arg, selected_value)
    for option in _get_option_entries(selector_arg):
        if option["label"] != selected_label:
            continue

        raw_option = option["raw"]
        if not isinstance(raw_option, dict):
            return set(), set()

        visible = {
            str(operation_args[index].get("name", ""))
            for index in raw_option.get("on", [])
            if isinstance(index, int) and 0 <= index < len(operation_args)
        }
        hidden = {
            str(operation_args[index].get("name", ""))
            for index in raw_option.get("off", [])
            if isinstance(index, int) and 0 <= index < len(operation_args)
        }
        return visible, hidden

    return set(), set()


def normalise_recipe_argument_value(arg: dict[str, Any], value: Any) -> Any:
    """Return a recipe argument value in the form CyberChef expects."""
    arg_type = str(arg.get("type", "string"))

    if arg_type in {"binaryString", "binaryShortString"} and isinstance(value, str):
        return decode_escaped_string(value)

    if arg_type == "boolean":
        return coerce_schema_boolean(value)

    if arg_type == "number" and isinstance(value, str):
        try:
            return int(value) if "." not in value else float(value)
        except ValueError:
            return value

    if arg_type in {
        "argSelector",
        "editableOption",
        "editableOptionShort",
        "option",
        "populateOption",
        "populateMultiOption",
    }:
        return canonicalise_option_value(arg, value)

    return value


def should_apply_schema_default(arg: dict[str, Any]) -> bool:
    """Return whether the bridge should materialise this argument's default."""
    return str(arg.get("type", "")) in {
        "argSelector",
        "binaryShortString",
        "binaryString",
        "boolean",
        "editableOption",
        "editableOptionShort",
        "populateMultiOption",
    }
