import asyncio
import inspect
import json
import os
import re
from collections.abc import Callable
from enum import IntEnum
from pathlib import Path
from typing import Any, TypedDict

import pythonmonkey as pm

from ida_cyberchef.core.schema_adapter import (
    decode_escaped_string,
    expand_populate_multi_option,
    get_argument_default_value,
    normalise_recipe_argument_value,
    sanitise_operation_name,
    should_apply_schema_default,
)

_chef_instance = None

_loop: asyncio.AbstractEventLoop | None = None

_js_helpers: dict[str, Any] = {}

# Upper bound on genuinely-asynchronous waiting for a JS promise to settle.
# Synchronous compute inside an operation blocks before the await and is not
# subject to this limit, matching the previous engine's drain-loop semantics.
PROMISE_TIMEOUT_SECONDS = 10.0


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


def _py_urandom_json(length: Any) -> str:
    """Return a JSON-encoded list of cryptographically random bytes."""
    num_bytes = int(length)
    if num_bytes < 0:
        raise ValueError("Random byte length must be non-negative")
    return json.dumps(list(os.urandom(num_bytes)))


def get_event_loop() -> asyncio.AbstractEventLoop:
    """Return the private event loop used to service the JS runtime.

    PythonMonkey resolves JS promises and runs SpiderMonkey's job queue
    through a running asyncio event loop, so every JS interaction that may
    touch promises is driven through this loop via run_js().
    """
    global _loop
    if _loop is None:
        _loop = asyncio.new_event_loop()
    return _loop


def run_js(thunk: Callable[[], Any]) -> Any:
    """Invoke a JS-touching callable inside the private event loop.

    If the callable returns a promise/awaitable, it is resolved before
    returning. This call is synchronous from the caller's perspective and
    must only be used from the main thread.

    Raises:
        pythonmonkey.SpiderMonkeyError: If the JS code throws or the promise
            rejects.
        RuntimeError: If a promise does not settle within
            PROMISE_TIMEOUT_SECONDS of asynchronous waiting.
    """

    async def invoke() -> Any:
        result = thunk()
        if inspect.isawaitable(result) or asyncio.isfuture(result):
            try:
                result = await asyncio.wait_for(result, timeout=PROMISE_TIMEOUT_SECONDS)
            except (asyncio.TimeoutError, TimeoutError) as exc:
                raise RuntimeError("Timed out waiting for CyberChef promise to settle") from exc
        if result is pm.null:
            return None
        return result

    return get_event_loop().run_until_complete(invoke())


def eval_js(code: str) -> Any:
    """Evaluate JS source inside the private event loop, resolving promises."""
    return run_js(lambda: pm.eval(code))


def _get_js_helper(name: str, source: str) -> Any:
    """Return a cached compiled JS helper function."""
    helper = _js_helpers.get(name)
    if helper is None:
        helper = pm.eval(source)
        _js_helpers[name] = helper
    return helper


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
    CyberChef export inside the private event loop, resolving any returned
    promise, so callers can use the API synchronously.
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
        if value is None:
            raise AttributeError(name)
        if callable(value):

            def call(*args: Any) -> Any:
                return run_js(lambda: value(*args))

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


def install_bake_helper() -> None:
    """Install an async-aware recipe executor in the JS runtime."""
    pm.eval("""
    module.exports.__piBake = async function(input, recipeConfig) {
        const sanitise = function(value) {
            return value.replace(/ /g, "").toLowerCase();
        };

        let current = input;

        for (const ingredient of recipeConfig) {
            let operationName;
            let args = null;

            if (typeof ingredient === "string") {
                operationName = ingredient;
            } else if (ingredient && typeof ingredient === "object" && ingredient.op) {
                operationName = ingredient.op;
                if (ingredient.args) {
                    args = ingredient.args;
                }
            } else {
                throw new TypeError("Recipe can only contain function names or functions");
            }

            const exportedOperationName = Object.keys(module.exports).find(function(candidateName) {
                const candidate = module.exports[candidateName];
                return typeof candidate === "function" &&
                    ![
                        "__piBake",
                        "bake",
                        "help",
                        "register",
                        "Dish",
                        "DishError",
                        "OperationError",
                        "ExcludedOperationError",
                    ].includes(candidateName) &&
                    sanitise(candidateName) === sanitise(operationName);
            });

            if (exportedOperationName) {
                const exportedOperation = module.exports[exportedOperationName];
                current = args ? exportedOperation(current, args) : exportedOperation(current);
            } else {
                const operation = module.exports.operations.find(function(candidate) {
                    return sanitise(candidate.opName) === sanitise(operationName);
                });

                if (!operation) {
                    throw new TypeError("Couldn't find an operation with name '" + operationName + "'.");
                }

                current = args ? operation(current, args) : operation(current);
            }

            if (current && typeof current.then === "function") {
                current = await current;
            }
        }

        return current;
    };
    """)


def load_cyberchef(path: str | None = None) -> Chef:
    """Load the CyberChef bundle into the JS runtime and return a Chef.

    Args:
        path: Path to CyberChef.js bundle. If None, uses package data path.

    Returns: Chef wrapper around the CyberChef module exports
    """
    if path is None:
        path = str(Path(__file__).parent / "data" / "CyberChef.js")

    pm.globalThis.py_urandom_json = _py_urandom_json  # type: ignore[attr-defined]

    # Setup minimal global environment for CyberChef. PythonMonkey already
    # provides timers (setTimeout and friends), atob/btoa, and WebAssembly.
    pm.eval("""
    globalThis.global = globalThis;
    globalThis.window = globalThis;
    globalThis.self = globalThis;
    globalThis.document = {};
    globalThis.app = {
        alert: function() {}
    };

    // Minimal process polyfill
    globalThis.process = {
        platform: 'linux',
        env: {},
        cwd: () => '/',
        version: 'v18.0.0',
        versions: {node: 'v18.0.0'},
        nextTick: function(fn) {
            const args = Array.prototype.slice.call(arguments, 1);
            Promise.resolve().then(function() {
                fn.apply(globalThis, args);
            });
        }
    };

    if (typeof setImmediate === 'undefined') {
        globalThis.setImmediate = function(fn) {
            const args = Array.prototype.slice.call(arguments, 1);
            return setTimeout(function() {
                fn.apply(globalThis, args);
            }, 0);
        };
        globalThis.clearImmediate = function(id) {
            clearTimeout(id);
        };
    }

    // TextEncoder/TextDecoder polyfill
    if (typeof TextEncoder === 'undefined') {
        globalThis.TextEncoder = class TextEncoder {
            encode(str) {
                const utf8 = unescape(encodeURIComponent(str));
                const result = new Uint8Array(utf8.length);
                for (let i = 0; i < utf8.length; i++) {
                    result[i] = utf8.charCodeAt(i);
                }
                return result;
            }
        };
    }

    if (typeof TextDecoder === 'undefined') {
        globalThis.TextDecoder = class TextDecoder {
            decode(bytes) {
                if (bytes instanceof ArrayBuffer) {
                    bytes = new Uint8Array(bytes);
                } else if (ArrayBuffer.isView(bytes)) {
                    bytes = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
                } else if (!bytes) {
                    bytes = [];
                }
                const utf8 = Array.from(bytes).map(b => String.fromCharCode(b)).join('');
                return decodeURIComponent(escape(utf8));
            }
        };
    }

    if (typeof Uint8Array !== 'undefined' && !Uint8Array.prototype.concat) {
        Uint8Array.prototype.concat = function() {
            const output = Array.from(this);
            for (let index = 0; index < arguments.length; index++) {
                const value = arguments[index];
                if (ArrayBuffer.isView(value)) {
                    output.push.apply(output, Array.from(value));
                } else if (Array.isArray(value)) {
                    output.push.apply(output, value);
                } else {
                    output.push(value);
                }
            }
            return output;
        };
    }

    // Crypto API polyfill. Only getRandomValues is bridged to Python's
    // os.urandom; crypto.subtle remains unavailable in this runtime.
    if (typeof crypto === 'undefined') {
        globalThis.crypto = {};
    }
    if (!globalThis.crypto.getRandomValues) {
        globalThis.crypto.getRandomValues = function(array) {
            const randomValues = JSON.parse(py_urandom_json(array.length));
            for (let i = 0; i < array.length; i++) {
                array[i] = randomValues[i];
            }
            return array;
        };
    }

    if (typeof performance === 'undefined') {
        const timeOrigin = Date.now();
        globalThis.performance = {
            timeOrigin: timeOrigin,
            now: function() {
                return Date.now() - timeOrigin;
            }
        };
    }

    if (!globalThis.__piLocaleComparePatched && String.prototype.localeCompare) {
        const originalLocaleCompare = String.prototype.localeCompare;
        String.prototype.localeCompare = function(compareString) {
            try {
                return originalLocaleCompare.apply(this, arguments);
            } catch (error) {
                const left = String(this);
                const right = String(compareString);
                if (left < right) return -1;
                if (left > right) return 1;
                return 0;
            }
        };
        globalThis.__piLocaleComparePatched = true;
    }

    // Setup minimal CommonJS environment
    globalThis.module = { exports: {} };
    """)

    # Load and execute CyberChef inside the event loop: the bundle schedules
    # promise jobs at load time, which SpiderMonkey services through asyncio.
    with open(path, "rb") as f:
        source = f.read().decode("utf-8")
    eval_js(source)
    install_bake_helper()

    exports = pm.eval("module.exports")
    return Chef(exports)


def convert_js_json_value(value: Any) -> Any:
    """Convert JSON-like JS values into native Python structures.

    Args:
        value: JS value returned by CyberChef.

    Returns:
        A Python-native JSON value.
    """
    stringify = _get_js_helper("json_stringify", "(v) => JSON.stringify(v)")
    json_text = run_js(lambda: stringify(value))

    if json_text is None:
        return None

    return json.loads(json_text)


def convert_js_file_value(value: Any) -> CyberChefFile | list[CyberChefFile] | Any:
    """Convert CyberChef File values into native Python structures.

    Args:
        value: JS File or File[] value returned by CyberChef.

    Returns:
        A Python file dict or list of file dicts.
    """
    convert = _get_js_helper(
        "convert_file",
        """
    (function(fileValue) {
        const convertFile = function(file) {
            return {
                name: file && file.name ? String(file.name) : "",
                type: file && file.type ? String(file.type) : "",
                data: file && file.data ? Array.from(file.data) : []
            };
        };

        if (Array.isArray(fileValue)) {
            return JSON.stringify(fileValue.map(convertFile));
        }

        return JSON.stringify(convertFile(fileValue));
    })
    """,
    )
    file_json = run_js(lambda: convert(value))
    parsed = json.loads(file_json)

    if isinstance(parsed, list):
        return [
            {
                "name": str(item.get("name", "")),
                "type": str(item.get("type", "")),
                "data": bytes(int(b) for b in item.get("data", [])),
            }
            for item in parsed
        ]

    return {
        "name": str(parsed.get("name", "")),
        "type": str(parsed.get("type", "")),
        "data": bytes(int(b) for b in parsed.get("data", [])),
    }


def _convert_js_array_buffer(value: Any) -> bytes:
    """Convert a JS ArrayBuffer or typed-array value to Python bytes."""
    convert = _get_js_helper(
        "array_buffer_to_json",
        "(v) => JSON.stringify(Array.from(new Uint8Array(v)))",
    )
    array_json = run_js(lambda: convert(value))
    return bytes(int(b) for b in json.loads(array_json))


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


def _native_str(s: str) -> str:
    # PythonMonkey on Linux returns broken string proxies from ICU-backed JS
    # operations (normalize, toLowerCase, etc.): content is correct but __hash__
    # and __eq__ are poisoned. Roundtripping through bytes produces a clean
    # native Python str.
    return s.encode("utf-8").decode("utf-8") if isinstance(s, str) else str(s)


def plate(v: Dish | Any, chef=None) -> Dish | Any:
    """Convert between Python types and CyberChef Dish objects.

    Args:
        v: Either a Dish object or a native Python type
        chef: Optional Chef instance for creating proper Dish instances from bytes

    Returns: Native Python type if input is Dish, Dish dict/instance if input is Python type
    """
    dish_type = None
    if isinstance(v, dict) and "value" in v and "type" in v:
        dish_type = _parse_dish_type(v["type"])
    elif hasattr(v, "value") and hasattr(v, "type"):
        dish_type = _parse_dish_type(v.type)

    if dish_type is not None:
        value = v["value"] if isinstance(v, dict) else v.value

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
            return _native_str(value)
        elif dish_type == DishType.NUMBER:
            return float(value)
        elif dish_type == DishType.HTML:
            return _native_str(value)
        elif dish_type == DishType.ARRAY_BUFFER:
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            if isinstance(value, list):
                return bytes(int(b) for b in value)
            if isinstance(value, dict) or hasattr(value, "__iter__"):
                return _convert_js_array_buffer(value)
            return value
        elif dish_type == DishType.BIG_NUMBER:
            if isinstance(value, (dict, list)):
                to_string = _get_js_helper("to_string", "(v) => String(v)")
                return str(run_js(lambda: to_string(value)))
            return str(value)
        elif dish_type == DishType.JSON:
            if isinstance(value, (dict, list)):
                return convert_js_json_value(value)
            return value
        elif dish_type == DishType.FILE or dish_type == DishType.LIST_FILE:
            return convert_js_file_value(value)
        else:
            return value
    else:
        if isinstance(v, bytes):
            if chef is not None:
                byte_json = json.dumps(list(v))
                make_dish = _get_js_helper(
                    "make_array_buffer_dish",
                    """
                (function(bytesJson) {
                    const byteArray = JSON.parse(bytesJson);
                    const uint8 = new Uint8Array(byteArray);
                    return new module.exports.Dish(uint8.buffer, module.exports.Dish.ARRAY_BUFFER);
                })
                """,
                )
                return run_js(lambda: make_dish(byte_json))
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
    bake_fn = _get_js_helper(
        "pi_bake",
        "(input, recipeJson) => module.exports.__piBake(input, JSON.parse(recipeJson))",
    )
    result = run_js(lambda: bake_fn(input_value, recipe_json))
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
    return _native_str(value)


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
