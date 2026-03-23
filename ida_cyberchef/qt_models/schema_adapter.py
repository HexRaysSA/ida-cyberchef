"""Shared schema normalization for widget-facing argument view models."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ida_cyberchef.cyberchef import (
    coerce_schema_boolean,
    decode_escaped_string,
    get_argument_default_index,
)


_MISSING = object()


@dataclass(frozen=True)
class SchemaOptionViewModel:
    """A readable option label paired with the runtime value it represents."""

    label: str
    value: Any


@dataclass(frozen=True)
class SchemaArgumentViewModel:
    """Normalized argument metadata used by recipe widgets."""

    name: str
    arg_type: str
    value: Any
    default_value: Any
    options: tuple[SchemaOptionViewModel, ...] = field(default_factory=tuple)
    toggle_values: tuple[str, ...] = field(default_factory=tuple)
    raw_argument: dict[str, Any] = field(default_factory=dict)


def _parse_schema_value(value: Any) -> Any:
    """Parse a JSON-encoded schema value when needed."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def _decode_runtime_string(value: Any) -> Any:
    """Decode CyberChef escape sequences for runtime string values."""
    if isinstance(value, str):
        return decode_escaped_string(value)
    return value


def _normalise_option_entry(arg_type: str, entry: Any) -> SchemaOptionViewModel:
    """Convert a raw schema option entry into a widget-facing choice."""
    if isinstance(entry, dict):
        label = str(entry.get("name", entry.get("value", "")))
        if arg_type == "populateMultiOption":
            return SchemaOptionViewModel(label=label, value=label)

        runtime_value = entry.get("value", label)
        return SchemaOptionViewModel(
            label=label,
            value=_decode_runtime_string(runtime_value),
        )

    runtime_value = _decode_runtime_string(entry)
    return SchemaOptionViewModel(label=str(entry), value=runtime_value)


def _normalise_option_values(arg: dict[str, Any]) -> tuple[SchemaOptionViewModel, ...]:
    """Return normalized choices for list-backed schema arguments."""
    raw_value = _parse_schema_value(arg.get("value", ""))
    if not isinstance(raw_value, list):
        return ()
    return tuple(
        _normalise_option_entry(str(arg.get("type", "string")), entry)
        for entry in raw_value
    )


def _normalise_toggle_values(arg: dict[str, Any]) -> tuple[str, ...]:
    """Return the available toggleString formats."""
    raw_values = _parse_schema_value(arg.get("toggleValues", []))
    if not isinstance(raw_values, list):
        return ()
    return tuple(str(value) for value in raw_values)


def get_default_argument_value(arg: dict[str, Any]) -> Any:
    """Return the normalized default value for an argument schema entry."""
    arg_type = str(arg.get("type", "string"))
    raw_value = _parse_schema_value(arg.get("value", ""))
    options = _normalise_option_values(arg)

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
            return options[default_index].value
        return raw_value

    if arg_type == "toggleString":
        toggle_values = _normalise_toggle_values(arg)
        if isinstance(raw_value, dict):
            return {
                "string": str(raw_value.get("string", "")),
                "option": str(
                    raw_value.get(
                        "option",
                        toggle_values[0] if toggle_values else "",
                    )
                ),
            }
        return {
            "string": _decode_runtime_string(raw_value) if raw_value else "",
            "option": toggle_values[0] if toggle_values else "",
        }

    return raw_value


def normalise_argument_view_model(
    arg: dict[str, Any],
    saved_value: Any = _MISSING,
) -> SchemaArgumentViewModel:
    """Build a widget-facing argument view model from raw schema and saved state."""
    if saved_value is _MISSING and "saved_value" in arg:
        saved_value = arg["saved_value"]

    default_value = get_default_argument_value(arg)
    value = default_value if saved_value is _MISSING else saved_value

    if str(arg.get("type", "string")) == "toggleString" and not isinstance(value, dict):
        value = {
            "string": str(value) if value is not None else "",
            "option": "",
        }

    return SchemaArgumentViewModel(
        name=str(arg["name"]),
        arg_type=str(arg.get("type", "string")),
        value=value,
        default_value=default_value,
        options=_normalise_option_values(arg),
        toggle_values=_normalise_toggle_values(arg),
        raw_argument=arg.copy(),
    )


def normalise_operation_view_model(
    operation: dict[str, Any],
    saved_args: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a shallow operation view model with normalized arguments."""
    saved_args = saved_args or {}
    operation_view = operation.copy()
    operation_args = []
    for arg in operation.get("args", []):
        if isinstance(arg, SchemaArgumentViewModel):
            operation_args.append(arg)
            continue
        operation_args.append(
            normalise_argument_view_model(
                arg,
                saved_args[arg["name"]] if arg["name"] in saved_args else _MISSING,
            )
        )
    operation_view["args"] = operation_args
    return operation_view


def get_operation_default_args(operation: dict[str, Any]) -> dict[str, Any]:
    """Return normalized default arguments for a schema operation."""
    return {
        arg_view.name: arg_view.default_value
        for arg_view in normalise_operation_view_model(operation).get("args", [])
    }
