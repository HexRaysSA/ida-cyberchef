"""Run CyberChef recipes in an embedded V8 engine.

`data/CyberChef.js` is CyberChef's core (all operations) bundled with the
small JS bridge in `js/`. It runs in a V8 isolate provided by mini-racer and
exposes `cyberchef.bake()`, which executes a recipe with CyberChef's own Recipe
class, so flow control, argument defaults and escape handling match the web
app.
"""

import atexit
import json
import os
from enum import IntEnum
from pathlib import Path
from typing import Any, TypedDict

from py_mini_racer import JSPromiseError, JSTimeoutException, MiniRacer

BUNDLE_PATH = Path(__file__).parent / "data" / "CyberChef.js"

# Upper bound on one bake, including time spent in asynchronous operations.
TIMEOUT_SECONDS = 30.0

Recipe = list[str | dict[str, Any]]
"""Operation names, or {"op": name, "args": {arg name: value}} (or positional args)."""


class CyberChefError(Exception):
    """A recipe failed; the message is CyberChef's error message."""


class CyberChefFile(TypedDict):
    """A file produced by an operation such as Unzip."""

    name: str
    type: str
    data: bytes


class DishType(IntEnum):
    """CyberChef's Dish type codes."""

    BYTE_ARRAY = 0
    STRING = 1
    NUMBER = 2
    HTML = 3
    ARRAY_BUFFER = 4
    BIG_NUMBER = 5
    JSON = 6
    FILE = 7
    LIST_FILE = 8


_runtime: MiniRacer | None = None
_bake: Any = None


def _get_bake() -> Any:
    """Return the JS bake function, loading CyberChef on first use (about a second)."""
    global _runtime, _bake
    if _bake is None:
        _runtime = MiniRacer()
        # An isolate that is never closed can stall interpreter shutdown.
        atexit.register(_runtime.close)
        _runtime.eval(BUNDLE_PATH.read_text(encoding="utf-8"))
        _bake = _runtime.eval("cyberchef.bake")
    return _bake


def _files(payload: Any) -> list[CyberChefFile]:
    meta, data = json.loads(payload[0]), bytes(payload[1])
    files: list[CyberChefFile] = []
    offset = 0
    for item in meta:
        end = offset + item["length"]
        files.append({"name": item["name"], "type": item["type"], "data": data[offset:end]})
        offset = end
    return files


def bake(input_data: bytes | str, recipe: Recipe) -> Any:
    """Run a recipe and return its output as a native Python value.

    Args:
        input_data: The recipe input. Text is passed to CyberChef as a string,
            bytes as an ArrayBuffer.
        recipe: The operations to run, for example
            `["From Base64", {"op": "XOR", "args": {"Key": {"option": "Hex", "string": "41"}}}]`.
            Arguments are matched by name, ignoring case and spaces, and the
            ones not given take their defaults from the web app.

    Returns:
        bytes, str, float, a JSON value, a CyberChefFile or a list of them,
        depending on the output type of the last operation.

    Raises:
        CyberChefError: An operation failed.
        TimeoutError: The recipe did not finish within TIMEOUT_SECONDS.
    """
    if not recipe:
        return input_data

    is_bytes = not isinstance(input_data, str)
    payload = input_data if isinstance(input_data, str) else bytes(input_data).decode("latin-1")
    try:
        promise = _get_bake()(payload, is_bytes, json.dumps(recipe), os.urandom(32).hex())
        dish_type, value = promise.get(timeout=TIMEOUT_SECONDS)
    except JSPromiseError as exc:
        raise CyberChefError(str(exc.reason)) from None
    except JSTimeoutException as exc:
        raise TimeoutError(f"CyberChef recipe did not finish within {TIMEOUT_SECONDS:g} seconds") from exc

    dish_type = DishType(dish_type)
    if dish_type in (DishType.BYTE_ARRAY, DishType.ARRAY_BUFFER):
        return bytes(value)
    if dish_type == DishType.NUMBER:
        return float(value)
    if dish_type == DishType.JSON:
        return json.loads(value)
    if dish_type == DishType.FILE:
        return _files(value)[0]
    if dish_type == DishType.LIST_FILE:
        return _files(value)
    return value
