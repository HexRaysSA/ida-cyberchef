import atexit
import json
import os
import re
from collections.abc import Callable
from enum import IntEnum
from pathlib import Path
from typing import Any, TypedDict

from py_mini_racer import (
    JSArray,
    JSEvalException,
    JSFunction,
    JSObject,
    JSPromise,
    JSPromiseError,
    JSTimeoutException,
    JSUndefined,
    MiniRacer,
)

from ida_cyberchef.core.schema_adapter import (
    decode_escaped_string,
    expand_populate_multi_option,
    get_argument_default_value,
    normalise_recipe_argument_value,
    sanitise_operation_name,
    should_apply_schema_default,
)

_chef_instance = None

_runtime: MiniRacer | None = None

_js_helpers: dict[str, Any] = {}

# Upper bound on genuinely-asynchronous waiting for a JS promise to settle.
# Synchronous compute inside an operation blocks before the await and is not
# subject to this limit.
PROMISE_TIMEOUT_SECONDS = 10.0


class JavaScriptError(Exception):
    """A CyberChef operation or other JS code threw an error."""


class DishType(IntEnum):
    """CyberChef Dish type enumeration."""

    BYTE_ARRAY = 0
    STRING = 1
    NUMBER = 2
    HTML = 3
    ARRAY_BUFFER = 4
    BIG_NUMBER = 5
    JSON = 6
    FILE = 7
    LIST_FILE = 8


class Dish(TypedDict):
    """CyberChef Dish object structure."""

    value: Any
    type: DishType


class CyberChefFile(TypedDict):
    """CyberChef file output represented as native Python data."""

    name: str
    type: str
    data: bytes


class RecipeOperation(TypedDict, total=False):
    """CyberChef recipe operation structure.

    Either a string operation name or a dict with op and args.
    """

    op: str
    args: dict[str, Any]


PYTHON_FLOW_CONTROL_OPERATIONS = {
    "Comment",
    "Conditional Jump",
    "Fork",
    "Jump",
    "Label",
    "Merge",
    "Return",
    "Subsection",
}

FLOW_CONTROL_DEFAULT_ARGUMENTS: dict[str, dict[str, Any]] = {
    "Comment": {"": ""},
    "Conditional Jump": {
        "Match (regex)": "",
        "Invert match": False,
        "Label name": "",
        "Maximum jumps (if jumping backwards)": 10,
    },
    "Fork": {"Split delimiter": "\n", "Merge delimiter": "\n", "Ignore errors": False},
    "Jump": {"Label name": "", "Maximum jumps (if jumping backwards)": 10},
    "Label": {"Name": ""},
    "Merge": {"Merge All": True},
    "Return": {},
    "Subsection": {
        "Section (regex)": "",
        "Case sensitive matching": True,
        "Global matching": True,
        "Ignore errors": False,
    },
}

_OPERATION_SCHEMA: dict[str, Any] | None = None
_OPERATION_SCHEMA_BY_NAME: dict[str, list[dict[str, Any]]] | None = None


def _random_seed_hex() -> str:
    """Return fresh OS entropy for the JS-side crypto.getRandomValues generator."""
    return os.urandom(32).hex()


def get_runtime() -> MiniRacer:
    """Return the V8 isolate that hosts CyberChef.

    mini-racer runs V8 on its own thread and serialises calls into it. The
    bridge's own module-level state is unlocked, so callers should still use
    it from one thread at a time.
    """
    global _runtime
    if _runtime is None:
        _runtime = MiniRacer()
        # An unclosed isolate can stall interpreter shutdown.
        atexit.register(close_runtime)
    return _runtime


def close_runtime() -> None:
    """Dispose of the V8 isolate and everything loaded into it."""
    global _runtime, _chef_instance
    runtime = _runtime
    _runtime = None
    _chef_instance = None
    _js_helpers.clear()
    if runtime is not None:
        runtime.close()


def _js_error_message(exc: Exception) -> str:
    """Return a concise message for an exception raised by mini-racer."""
    if isinstance(exc, JSPromiseError):
        return str(exc.reason).strip()

    # Synchronous errors look like "<anonymous>:LINE: Name: message\n<source>\n   ^\n\n<stack>".
    message = str(exc)
    first_line = message.split("\n", 1)[0]
    return re.sub(r"^<anonymous>:\d+: (Uncaught )?", "", first_line)


def run_js(thunk: Callable[[], Any]) -> Any:
    """Invoke a JS-touching callable and resolve any returned promise.

    This call is synchronous from the caller's perspective. JS `undefined`
    and `null` are both returned as None.

    Raises:
        JavaScriptError: If the JS code throws or the promise rejects.
        RuntimeError: If a promise does not settle within
            PROMISE_TIMEOUT_SECONDS of asynchronous waiting.
    """
    try:
        result = thunk()
        if isinstance(result, JSPromise):
            result = result.get(timeout=PROMISE_TIMEOUT_SECONDS)
    except JSTimeoutException as exc:
        raise RuntimeError("Timed out waiting for CyberChef promise to settle") from exc
    except (JSEvalException, JSPromiseError) as exc:
        raise JavaScriptError(_js_error_message(exc)) from exc

    if result is JSUndefined:
        return None
    return result


def eval_js(code: str) -> Any:
    """Evaluate JS source in the CyberChef runtime, resolving promises."""
    return run_js(lambda: get_runtime().eval(code))


def _get_js_helper(name: str, source: str | None = None) -> Any:
    """Return a cached compiled JS helper function.

    Without `source`, `name` refers to a global defined by runtime.js.
    """
    helper = _js_helpers.get(name)
    if helper is None:
        helper = get_runtime().eval(source if source is not None else name)
        _js_helpers[name] = helper
    return helper


def to_js(value: Any) -> Any:
    """Convert a Python value into a value that can be passed to JS.

    Primitives and JS object handles pass through unchanged; bytes become an
    ArrayBuffer and other values are converted via JSON.
    """
    if value is None or isinstance(value, (bool, int, float, str, JSObject)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return run_js(lambda: _get_js_helper("__piBytes")(bytes(value).decode("latin-1")))
    return run_js(lambda: _get_js_helper("__piJson")(json.dumps(value)))


def call_js(function: Any, *args: Any) -> Any:
    """Call a JS function with Python arguments, resolving any returned promise.

    Errors are reported as JavaScriptError with a "Name: message" text.
    """
    js_args = [to_js(arg) for arg in args]
    invoke = _get_js_helper("__piCall")
    return run_js(lambda: invoke(function, *js_args))


def get_operation_schema() -> dict[str, Any]:
    """Load the generated operation schema."""
    global _OPERATION_SCHEMA
    if _OPERATION_SCHEMA is None:
        schema_path = Path(__file__).parent / "data" / "operation_schema.json"
        _OPERATION_SCHEMA = json.loads(schema_path.read_text())
    return _OPERATION_SCHEMA


def get_operation_schema_by_name() -> dict[str, list[dict[str, Any]]]:
    """Index schema operations by sanitised operation name."""
    global _OPERATION_SCHEMA_BY_NAME
    if _OPERATION_SCHEMA_BY_NAME is None:
        operations = get_operation_schema().get("operations", [])
        schema_by_name: dict[str, list[dict[str, Any]]] = {}
        for operation in operations:
            schema_by_name.setdefault(sanitise_operation_name(str(operation.get("name", ""))), []).append(operation)
        _OPERATION_SCHEMA_BY_NAME = schema_by_name
    return _OPERATION_SCHEMA_BY_NAME


def get_schema_operation(name: str) -> dict[str, Any] | None:
    """Return schema metadata for an operation name."""
    return get_operation_schema_by_name().get(sanitise_operation_name(name), [None])[0]


def canonicalise_argument_name(args: list[dict[str, Any]], key: str) -> str | None:
    """Return the canonical schema argument name for a provided key."""
    sanitised_key = sanitise_operation_name(key)
    for arg in args:
        arg_name = str(arg.get("name", ""))
        if sanitise_operation_name(arg_name) == sanitised_key:
            return arg_name
    return None


def normalise_js_recipe_operation(operation: str | RecipeOperation) -> str | RecipeOperation:
    """Normalise a JS-backed recipe operation against schema metadata."""
    if isinstance(operation, str):
        name = operation
        provided_args: dict[str, Any] = {}
    elif isinstance(operation, dict) and "op" in operation:
        name = str(operation["op"])
        provided_args = dict(operation.get("args", {}))
    else:
        raise TypeError("Recipe can only contain function names or functions")

    schema_operation = get_schema_operation(name)
    if not schema_operation:
        return operation

    schema_args = list(schema_operation.get("args", []))
    if not schema_args and isinstance(operation, str):
        return operation

    provided_by_name: dict[str, Any] = {}
    extra_args: dict[str, Any] = {}

    for key, value in provided_args.items():
        canonical_name = canonicalise_argument_name(schema_args, key)
        if canonical_name is None:
            extra_args[key] = value
            continue
        provided_by_name[canonical_name] = value

    populate_expansions: dict[str, Any] = {}
    for arg in schema_args:
        arg_name = str(arg.get("name", ""))
        if str(arg.get("type", "")) != "populateMultiOption" or arg_name not in provided_by_name:
            continue
        for target_index, expanded_value in expand_populate_multi_option(arg, provided_by_name[arg_name]).items():
            try:
                target_name = str(schema_args[int(target_index)].get("name", ""))
            except (IndexError, ValueError):
                continue
            populate_expansions.setdefault(target_name, expanded_value)

    normalised_args = dict(extra_args)

    for arg in schema_args:
        arg_name = str(arg.get("name", ""))
        if arg_name in provided_by_name:
            normalised_args[arg_name] = normalise_recipe_argument_value(arg, provided_by_name[arg_name])
            continue
        if arg_name in populate_expansions:
            normalised_args[arg_name] = normalise_recipe_argument_value(arg, populate_expansions[arg_name])
            continue
        if should_apply_schema_default(arg):
            normalised_args[arg_name] = get_argument_default_value(arg)

    if not normalised_args:
        return name

    return {"op": name, "args": normalised_args}


def normalise_js_recipe(recipe: list[str | RecipeOperation]) -> list[str | RecipeOperation]:
    """Return a JS-backed recipe with bridge-compatible argument defaults."""
    return [normalise_js_recipe_operation(operation) for operation in recipe]


class Chef:
    """Python-facing wrapper around CyberChef's module.exports.

    Attribute access returns callables that execute the corresponding
    CyberChef export, resolving any returned promise, so callers can use the
    API synchronously.
    """

    def __init__(self, exports: Any):
        self.exports = exports

    def operation_names(self) -> list[str]:
        """Return the names of all exported attributes."""
        keys = run_js(lambda: _get_js_helper("object_keys", "(o) => JSON.stringify(Object.keys(o))")(self.exports))
        return list(json.loads(keys))

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            value = self.exports[name]
        except (KeyError, TypeError) as exc:
            raise AttributeError(name) from exc
        if value is None or value is JSUndefined:
            raise AttributeError(name)
        if isinstance(value, JSFunction):

            def call(*args: Any) -> Any:
                return call_js(value, *args)

            return call
        return value


def get_chef() -> Chef:
    """Get or create a cached CyberChef instance.

    Returns: Chef wrapper around the CyberChef module exports
    """
    global _chef_instance
    if _chef_instance is None:
        _chef_instance = load_cyberchef()
    return _chef_instance


def load_cyberchef(path: str | None = None) -> Chef:
    """Load the CyberChef bundle into the JS runtime and return a Chef.

    Args:
        path: Path to CyberChef.js bundle. If None, uses package data path.

    Returns: Chef wrapper around the CyberChef module exports
    """
    data_dir = Path(__file__).parent / "data"
    if path is None:
        path = str(data_dir / "CyberChef.js")

    # Install browser/Node.js API polyfills and the bridge helpers, then
    # load the bundle, which populates module.exports.
    eval_js((data_dir / "runtime.js").read_text(encoding="utf-8"))
    run_js(lambda: _get_js_helper("__piSeedRandom")(_random_seed_hex()))
    eval_js(Path(path).read_text(encoding="utf-8"))

    exports = eval_js("module.exports")
    return Chef(exports)


def convert_js_json_value(value: Any) -> Any:
    """Convert JSON-like JS values into native Python structures.

    Args:
        value: JS value returned by CyberChef.

    Returns:
        A Python-native JSON value.
    """
    if not isinstance(value, JSObject):
        return value

    stringify = _get_js_helper("json_stringify", "(v) => JSON.stringify(v)")
    json_text = run_js(lambda: stringify(value))

    if json_text is None:
        return None

    return json.loads(json_text)


def _convert_files(payload: Any) -> CyberChefFile | list[CyberChefFile]:
    """Convert an exported File/File[] payload into native Python structures."""
    meta = json.loads(payload[0])
    data = bytes(payload[1])

    files: list[CyberChefFile] = []
    offset = 0
    for item in meta["files"]:
        length = int(item["length"])
        files.append({"name": str(item["name"]), "type": str(item["type"]), "data": data[offset : offset + length]})
        offset += length

    if meta["list"]:
        return files
    return files[0]


def _plate_js_value(v: Any) -> Any:
    """Convert a JS value (usually a Dish) into a native Python value."""
    export = _get_js_helper("__piExport")
    exported = run_js(lambda: export(v))
    kind = exported[0]

    if kind == "bytes":
        return bytes(exported[1])
    if kind == "json":
        return plate(json.loads(exported[1]))
    if kind == "string":
        return plate(exported[1])

    dish_type = DishType(int(exported[1]))
    value = exported[2]

    if dish_type in (DishType.BYTE_ARRAY, DishType.ARRAY_BUFFER):
        if isinstance(value, memoryview):
            return bytes(value)
        if isinstance(value, JSArray):
            # JS numbers are doubles; mini-racer returns int32-representable ones as int.
            values = [float(b) if isinstance(b, int) and not isinstance(b, bool) else b for b in value]
            return plate({"value": values, "type": dish_type})
        return value
    if dish_type in (DishType.STRING, DishType.HTML, DishType.BIG_NUMBER):
        return value
    if dish_type == DishType.NUMBER:
        return float(value)
    if dish_type == DishType.JSON:
        return json.loads(value)
    if dish_type in (DishType.FILE, DishType.LIST_FILE):
        return _convert_files(value)
    return value


def _parse_dish_type(raw_type: Any) -> DishType | None:
    """Return a valid DishType for a raw Dish type value, if possible."""
    if isinstance(raw_type, bool):
        return None
    if isinstance(raw_type, float) and not raw_type.is_integer():
        return None

    try:
        return DishType(int(raw_type))
    except (TypeError, ValueError):
        return None


def plate(v: Dish | Any, chef=None) -> Dish | Any:
    """Convert between Python types and CyberChef Dish objects.

    Args:
        v: Either a Dish object or a native Python type
        chef: Optional Chef instance for creating proper Dish instances from bytes

    Returns: Native Python type if input is Dish, Dish dict/instance if input is Python type
    """
    if isinstance(v, JSObject):
        return _plate_js_value(v)

    dish_type = None
    if isinstance(v, dict) and "value" in v and "type" in v:
        dish_type = _parse_dish_type(v["type"])

    if dish_type is not None:
        value = v["value"]

        if dish_type == DishType.BYTE_ARRAY:
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            if isinstance(value, list) or hasattr(value, "__iter__"):
                value_list = list(value) if not isinstance(value, list) else value
                if value_list and isinstance(value_list[0], float):
                    return bytes(int(v) for v in value_list)
                elif value_list and isinstance(value_list[0], int):
                    return bytes(value_list)
                elif value_list:
                    raise NotImplementedError
                return b""

            return value
        elif dish_type == DishType.STRING:
            return str(value)
        elif dish_type == DishType.NUMBER:
            return float(value)
        elif dish_type == DishType.HTML:
            return str(value)
        elif dish_type == DishType.ARRAY_BUFFER:
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            if isinstance(value, list):
                return bytes(int(b) for b in value)
            return value
        elif dish_type == DishType.BIG_NUMBER:
            return str(value)
        else:
            return value
    else:
        if isinstance(v, bytes):
            if chef is not None:
                make_dish = _get_js_helper("__piMakeBytesDish")
                return run_js(lambda: make_dish(v.decode("latin-1")))
            else:
                return {"value": list(v), "type": DishType.ARRAY_BUFFER}
        elif isinstance(v, str):
            return {"value": v, "type": DishType.STRING}
        elif isinstance(v, (int, float)):
            return {"value": v, "type": DishType.NUMBER}
        elif isinstance(v, (dict, list)):
            return {"value": v, "type": DishType.JSON}
        else:
            return {"value": str(v), "type": DishType.STRING}


def normalise_recipe_operation(operation: str | RecipeOperation) -> tuple[str, dict[str, Any]]:
    """Return a recipe operation name and merged argument mapping.

    Args:
        operation: Recipe operation configuration.

    Returns:
        The operation name and a shallow copy of its arguments with defaults applied
        for Python-implemented flow-control operations.

    Raises:
        TypeError: If the recipe entry is not a supported string or dict shape.

    """
    if isinstance(operation, str):
        return operation, dict(FLOW_CONTROL_DEFAULT_ARGUMENTS.get(operation, {}))

    if not isinstance(operation, dict) or "op" not in operation:
        raise TypeError("Recipe can only contain function names or functions")

    name = str(operation["op"])
    args = dict(FLOW_CONTROL_DEFAULT_ARGUMENTS.get(name, {}))
    args.update(operation.get("args", {}))
    return name, args


def contains_python_flow_control(recipe: list[str | RecipeOperation]) -> bool:
    """Return whether a recipe uses Python-emulated flow control.

    Args:
        recipe: Recipe to inspect.

    Returns:
        True when the recipe contains a flow-control operation implemented in
        Python.

    """
    return any(normalise_recipe_operation(operation)[0] in PYTHON_FLOW_CONTROL_OPERATIONS for operation in recipe)


def bake_js_recipe(input_data: bytes | str, recipe: list[str | RecipeOperation]) -> Any:
    """Execute a recipe through the Node-targeted CyberChef API.

    Args:
        input_data: Input data as bytes or string.
        recipe: Recipe without Python-emulated flow control.

    Returns:
        Native Python data matching the final CyberChef output type.

    """
    chef = get_chef()

    if isinstance(input_data, bytes):
        input_value = plate(input_data, chef)
    else:
        input_value = input_data

    normalised_recipe = normalise_js_recipe(recipe)
    recipe_json = json.dumps(normalised_recipe)
    result = call_js(_get_js_helper("__piBake"), input_value, recipe_json, _random_seed_hex())
    return plate(result, chef)


def coerce_string_value(value: Any) -> str:
    """Convert a recipe value to the string representation used by flow control.

    Args:
        value: Value to convert.

    Returns:
        A string suitable for Python-emulated flow-control operations.

    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def find_label_index(recipe: list[str | RecipeOperation], label_name: str) -> int:
    """Return the index of the first matching Label operation.

    Args:
        recipe: Recipe to inspect.
        label_name: Label name to search for.

    Returns:
        The label index, or -1 when the label is absent.

    """
    for index, operation in enumerate(recipe):
        name, args = normalise_recipe_operation(operation)
        if name == "Label" and args.get("Name", "") == label_name:
            return index
    return -1


def collect_flow_subrecipe(
    recipe: list[str | RecipeOperation],
    start_index: int,
) -> tuple[list[str | RecipeOperation], int]:
    """Return the subrecipe controlled by a Fork or Subsection.

    Args:
        recipe: Full recipe.
        start_index: Index of the Fork or Subsection operation.

    Returns:
        The controlled subrecipe and the index immediately after its matching
        Merge, or the recipe length when no matching Merge is present.

    """
    depth = 1
    subrecipe: list[str | RecipeOperation] = []

    for index in range(start_index + 1, len(recipe)):
        name, args = normalise_recipe_operation(recipe[index])

        if name == "Merge":
            depth -= 1
            if depth == 0 or bool(args.get("Merge All", True)):
                return subrecipe, index + 1
            subrecipe.append(recipe[index])
            continue

        if name in {"Fork", "Subsection"}:
            depth += 1
        subrecipe.append(recipe[index])

    return subrecipe, len(recipe)


def execute_python_flow_recipe(input_data: bytes | str, recipe: list[str | RecipeOperation]) -> Any:
    """Execute a recipe containing Python-emulated flow-control operations.

    Args:
        input_data: Input data as bytes or string.
        recipe: Recipe to execute.

    Returns:
        Native Python data matching the final CyberChef output type.

    Raises:
        re.error: If a flow-control regex is invalid.

    """
    current: Any = input_data
    index = 0
    num_jumps = 0

    while index < len(recipe):
        operation = recipe[index]
        name, args = normalise_recipe_operation(operation)

        if name not in PYTHON_FLOW_CONTROL_OPERATIONS:
            current = bake_js_recipe(current, [operation])
            index += 1
            continue

        if name in {"Comment", "Label", "Merge"}:
            index += 1
            continue

        if name == "Return":
            break

        if name == "Jump":
            label_index = find_label_index(recipe, str(args.get("Label name", "")))
            max_jumps = int(args.get("Maximum jumps (if jumping backwards)", 10))
            if num_jumps >= max_jumps or label_index == -1:
                num_jumps = 0
                index += 1
            else:
                num_jumps += 1
                index = label_index + 1
            continue

        if name == "Conditional Jump":
            label_index = find_label_index(recipe, str(args.get("Label name", "")))
            max_jumps = int(args.get("Maximum jumps (if jumping backwards)", 10))
            pattern = str(args.get("Match (regex)", ""))
            invert = bool(args.get("Invert match", False))

            if num_jumps >= max_jumps or label_index == -1:
                num_jumps = 0
                index += 1
                continue

            matched = bool(pattern) and re.search(pattern, coerce_string_value(current)) is not None
            if pattern and ((matched and not invert) or (not matched and invert)):
                num_jumps += 1
                index = label_index + 1
            else:
                num_jumps = 0
                index += 1
            continue

        if name == "Fork":
            split_delimiter = decode_escaped_string(str(args.get("Split delimiter", "\\n")))
            merge_delimiter = decode_escaped_string(str(args.get("Merge delimiter", "\\n")))
            ignore_errors = bool(args.get("Ignore errors", False))
            subrecipe, next_index = collect_flow_subrecipe(recipe, index)
            inputs = coerce_string_value(current).split(split_delimiter) if current else []
            outputs = []

            for branch_input in inputs:
                try:
                    branch_output = bake(branch_input, subrecipe)
                except Exception:
                    if not ignore_errors:
                        raise
                    continue
                outputs.append(coerce_string_value(branch_output))

            current = merge_delimiter.join(outputs)
            index = next_index
            continue

        if name == "Subsection":
            section = str(args.get("Section (regex)", ""))
            case_sensitive = bool(args.get("Case sensitive matching", True))
            global_matching = bool(args.get("Global matching", True))
            ignore_errors = bool(args.get("Ignore errors", False))
            subrecipe, next_index = collect_flow_subrecipe(recipe, index)

            if not current or section == "":
                index += 1
                continue

            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(section, flags)
            input_text = coerce_string_value(current)
            matches = list(regex.finditer(input_text)) if global_matching else [regex.search(input_text)]
            matches = [match for match in matches if match is not None]

            if not matches:
                index = next_index
                continue

            output_parts = []
            input_offset = 0

            for match in matches:
                capture_group = 1 if match.lastindex else 0
                start, end = match.span(capture_group)
                output_parts.append(input_text[input_offset:start])
                section_text = input_text[start:end]

                try:
                    section_output = bake(section_text, subrecipe)
                except Exception:
                    if not ignore_errors:
                        raise
                    section_output = section_text

                output_parts.append(coerce_string_value(section_output))
                input_offset = end

                if not global_matching:
                    break

            output_parts.append(input_text[input_offset:])
            current = "".join(output_parts)
            index = next_index
            continue

        raise NotImplementedError(f"Unsupported Python flow-control operation: {name}")

    return current


def bake(input_data: bytes | str, recipe: list[str | RecipeOperation]) -> Any:
    """Execute CyberChef operations using the loaded JS runtime.

    Args:
        input_data: Input data as bytes or string
        recipe: List of operations. Each operation is either:
            - A string operation name: "To Base64"
            - A dict with op and args: {"op": "SHA2", "args": {"size": 256}}

    Returns:
        Native Python data matching the final CyberChef output type.
    """
    if not recipe:
        return input_data

    if contains_python_flow_control(recipe):
        return execute_python_flow_recipe(input_data, recipe)

    return bake_js_recipe(input_data, recipe)
