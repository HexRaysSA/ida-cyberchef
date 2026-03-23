"""Typed output model for CyberChef recipe results."""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any


class OutputKind(Enum):
    BYTES = auto()
    TEXT = auto()
    NUMBER = auto()
    JSON = auto()
    FILE = auto()
    FILE_LIST = auto()
    ERROR = auto()


@dataclass
class TypedOutput:
    kind: OutputKind
    value: Any


def _is_cyberchef_file(v: Any) -> bool:
    """Return True if v looks like a CyberChef file dict."""
    return isinstance(v, dict) and "name" in v and "type" in v and "data" in v


def typed_output_from_value(value: Any) -> TypedOutput:
    """Wrap a value returned by plate() in a TypedOutput with an inferred kind.

    Args:
        value: Native Python value produced by cyberchef.plate().

    Returns:
        A TypedOutput with the appropriate OutputKind.
    """
    if isinstance(value, bytes):
        return TypedOutput(kind=OutputKind.BYTES, value=value)
    if isinstance(value, str):
        return TypedOutput(kind=OutputKind.TEXT, value=value)
    if isinstance(value, (int, float)):
        return TypedOutput(kind=OutputKind.NUMBER, value=value)
    if isinstance(value, list):
        if value and all(_is_cyberchef_file(item) for item in value):
            return TypedOutput(kind=OutputKind.FILE_LIST, value=value)
        return TypedOutput(kind=OutputKind.JSON, value=value)
    if _is_cyberchef_file(value):
        return TypedOutput(kind=OutputKind.FILE, value=value)
    if isinstance(value, dict):
        return TypedOutput(kind=OutputKind.JSON, value=value)
    return TypedOutput(kind=OutputKind.TEXT, value=str(value))
