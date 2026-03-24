"""Shared schema normalization for widget-facing argument view models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ida_cyberchef.core.schema_adapter import (
    get_argument_default_value as get_shared_argument_default_value,
    get_display_items,
    get_option_value_for_display,
    get_toggle_values,
    restore_saved_argument_value,
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


def _normalise_option_values(arg: dict[str, Any]) -> tuple[SchemaOptionViewModel, ...]:
    """Return normalized choices for list-backed schema arguments."""
    return tuple(
        SchemaOptionViewModel(
            label=display_label,
            value=get_option_value_for_display(arg, display_label),
        )
        for display_label in get_display_items(arg)
    )


def get_default_argument_value(arg: dict[str, Any]) -> Any:
    """Return the normalized default value for an argument schema entry."""
    return get_shared_argument_default_value(arg)


def normalise_argument_view_model(
    arg: dict[str, Any],
    saved_value: Any = _MISSING,
) -> SchemaArgumentViewModel:
    """Build a widget-facing argument view model from raw schema and saved state."""
    if saved_value is _MISSING and "saved_value" in arg:
        saved_value = arg["saved_value"]

    default_value = get_default_argument_value(arg)
    value = default_value if saved_value is _MISSING else restore_saved_argument_value(arg, saved_value)

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
        toggle_values=get_toggle_values(arg),
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
        arg_view.name: arg_view.default_value for arg_view in normalise_operation_view_model(operation).get("args", [])
    }
