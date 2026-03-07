import json
import re
from enum import IntEnum
from typing import Any, TypedDict

import STPyV8

_chef_instance = None

_NODE_API_SYNC_WRAPPER_OLD = """    wrapped = function wrapped(input) {
      var args = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
      var _prepareOp2 = prepareOp(opInstance, input, args),
        transformedInput = _prepareOp2.transformedInput,
        transformedArgs = _prepareOp2.transformedArgs;
      var result = opInstance.run(transformedInput, transformedArgs);
      return new _NodeDish.default({
        value: result,
        type: opInstance.outputType
      });
    };"""

_NODE_API_SYNC_WRAPPER_NEW = """    wrapped = function wrapped(input) {
      var args = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : null;
      var _prepareOp2 = prepareOp(opInstance, input, args),
        transformedInput = _prepareOp2.transformedInput,
        transformedArgs = _prepareOp2.transformedArgs;
      var result = opInstance.run(transformedInput, transformedArgs);
      if (result && typeof result.then === \"function\") {
        return result.then(function (resolvedResult) {
          return new _NodeDish.default({
            value: resolvedResult,
            type: opInstance.outputType
          });
        });
      }
      return new _NodeDish.default({
        value: result,
        type: opInstance.outputType
      });
    };"""


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


def get_chef():
    """Get or create a cached CyberChef instance.

    Returns: CyberChef module exports object
    """
    global _chef_instance
    if _chef_instance is None:
        _chef_instance = load_cyberchef()
    return _chef_instance


def patch_bundle_source(source: str) -> str:
    """Patch bundled CyberChef code for STPyV8 execution.

    Raises:
        RuntimeError: If the expected node wrapper snippet is not present.
    """
    if _NODE_API_SYNC_WRAPPER_OLD not in source:
        raise RuntimeError("Failed to patch CyberChef async operation wrapper")

    source = source.replace(_NODE_API_SYNC_WRAPPER_OLD, _NODE_API_SYNC_WRAPPER_NEW, 1)
    return source.replace(
        "window.app.options.attemptHighlight = false;",
        "window.app&&window.app.options&&(window.app.options.attemptHighlight=false);",
        2,
    )


def install_bake_helper(ctx: STPyV8.JSContext) -> None:
    """Install an async-aware recipe executor in the JS context."""
    ctx.eval("""
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

            const operation = module.exports.operations.find(function(candidate) {
                return sanitise(candidate.opName) === sanitise(operationName);
            });

            if (!operation) {
                throw new TypeError("Couldn't find an operation with name '" + operationName + "'.");
            }

            current = args ? operation(current, args) : operation(current);

            if (current && typeof current.then === "function") {
                current = await current;
            }
        }

        return current;
    };
    """)


def await_js_promise(ctx: STPyV8.JSContext, expression: str) -> Any:
    """Resolve a promise or plain JS value inside the active context.

    Raises:
        RuntimeError: If the value does not settle within the polling limit.
    """
    ctx.eval(f"""
    globalThis.__piPromisePending = true;
    globalThis.__piPromiseResult = undefined;
    globalThis.__piPromiseError = undefined;
    Promise.resolve({expression}).then(
        function(result) {{
            globalThis.__piPromiseResult = result;
            globalThis.__piPromisePending = false;
        }},
        function(error) {{
            globalThis.__piPromiseError = error;
            globalThis.__piPromisePending = false;
        }}
    );
    """)

    for _ in range(1000):
        if not ctx.eval("globalThis.__piPromisePending"):
            break
    else:
        raise RuntimeError("Timed out waiting for CyberChef promise to settle")

    return ctx.eval("""
    (function() {
        if (globalThis.__piPromiseError !== undefined) {
            throw globalThis.__piPromiseError;
        }
        return globalThis.__piPromiseResult;
    })
    """)()


def load_cyberchef(path: str | None = None):
    """Load CyberChef bundle into V8 context and return exports.

    Args:
        path: Path to CyberChef.js bundle. If None, uses package data path.

    Returns: CyberChef module exports object
    """
    if path is None:
        from pathlib import Path

        path = str(Path(__file__).parent / "data" / "CyberChef.js")
    ctx = STPyV8.JSContext()
    ctx.enter()

    # Setup minimal global environment for CyberChef
    ctx.eval("""
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
        nextTick: (fn) => setTimeout(fn, 0)
    };

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

    // Crypto API polyfill
    if (typeof crypto === 'undefined') {
        globalThis.crypto = {};
    }
    if (!globalThis.crypto.getRandomValues) {
        globalThis.crypto.getRandomValues = function(array) {
            for (let i = 0; i < array.length; i++) {
                array[i] = Math.floor(Math.random() * 256);
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

    if (typeof WebAssembly !== 'undefined') {
        WebAssembly.compile = function(source) {
            try {
                return Promise.resolve(new WebAssembly.Module(source));
            } catch (error) {
                return Promise.reject(error);
            }
        };
        WebAssembly.instantiate = function(source, imports) {
            try {
                if (source instanceof WebAssembly.Module) {
                    return Promise.resolve(new WebAssembly.Instance(source, imports));
                }
                const module = new WebAssembly.Module(source);
                return Promise.resolve({
                    module: module,
                    instance: new WebAssembly.Instance(module, imports),
                });
            } catch (error) {
                return Promise.reject(error);
            }
        };
    }

    // Timer polyfills (minimal implementation for CyberChef)
    globalThis.setTimeout = function(fn, ms) {
        fn();
        return 0;
    };
    globalThis.setInterval = function(fn, ms) {
        return 0;
    };
    globalThis.clearTimeout = function(id) {};
    globalThis.clearInterval = function(id) {};
    """)

    # Setup minimal CommonJS environment
    ctx.eval("const module = { exports: {} };")

    # Load and execute CyberChef
    with open(path, "rb") as f:
        source = patch_bundle_source(f.read().decode("utf-8"))
    ctx.eval(source)
    install_bake_helper(ctx)

    # Extract exports and attach context for later use
    chef = ctx.eval("module.exports")
    chef._stpyv8_context = ctx
    return chef


def convert_js_json_value(value: Any, chef: Any) -> Any:
    """Convert JSON-like JS values into native Python structures.

    Args:
        value: JS value returned by CyberChef.
        chef: Loaded CyberChef module with an attached STPyV8 context.

    Returns:
        A Python-native JSON value when a JS context is available.
    """
    if not chef or not hasattr(chef, "_stpyv8_context"):
        return value

    ctx = chef._stpyv8_context
    ctx.locals.json_value = value
    json_text = ctx.eval("""
    (function() {
        return JSON.stringify(json_value);
    })
    """)()

    if json_text is None:
        return None

    return json.loads(json_text)


def convert_js_file_value(value: Any, chef: Any) -> CyberChefFile | list[CyberChefFile] | Any:
    """Convert CyberChef File values into native Python structures.

    Args:
        value: JS File or File[] value returned by CyberChef.
        chef: Loaded CyberChef module with an attached STPyV8 context.

    Returns:
        A Python file dict or list of file dicts when a JS context is available.
    """
    if not chef or not hasattr(chef, "_stpyv8_context"):
        return value

    ctx = chef._stpyv8_context
    ctx.locals.file_value = value
    file_json = ctx.eval("""
    (function() {
        const convertFile = function(file) {
            return {
                name: file && file.name ? String(file.name) : "",
                type: file && file.type ? String(file.type) : "",
                data: file && file.data ? Array.from(file.data) : []
            };
        };

        if (Array.isArray(file_value)) {
            return JSON.stringify(file_value.map(convertFile));
        }

        return JSON.stringify(convertFile(file_value));
    })
    """)()
    parsed = json.loads(file_json)

    if isinstance(parsed, list):
        return [
            {
                "name": str(item.get("name", "")),
                "type": str(item.get("type", "")),
                "data": bytes(item.get("data", [])),
            }
            for item in parsed
        ]

    return {
        "name": str(parsed.get("name", "")),
        "type": str(parsed.get("type", "")),
        "data": bytes(parsed.get("data", [])),
    }


def plate(v: Dish | Any, chef=None) -> Dish | Any:
    """Convert between Python types and CyberChef Dish objects.

    Args:
        v: Either a Dish object or a native Python type
        chef: Optional CyberChef module for creating proper Dish instances from bytes

    Returns: Native Python type if input is Dish, Dish dict/instance if input is Python type
    """
    is_dish_object = (isinstance(v, dict) and "value" in v and "type" in v) or (
        hasattr(v, "value") and hasattr(v, "type")
    )

    if is_dish_object:
        dish_type = DishType(int(v["type"] if isinstance(v, dict) else v.type))
        value = v["value"] if isinstance(v, dict) else v.value

        if dish_type == DishType.BYTE_ARRAY:
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
            if isinstance(value, STPyV8.JSObject):
                if chef and hasattr(chef, "_stpyv8_context"):
                    ctx = chef._stpyv8_context
                    ctx.locals.array_buffer_value = value
                    array_data = ctx.eval("""
                    (function() {
                        return Array.from(new Uint8Array(array_buffer_value));
                    })
                    """)()
                    return bytes(list(array_data))
                else:
                    return value
            elif isinstance(value, list) or hasattr(value, "__iter__"):
                return bytes(list(value))
            return value
        elif dish_type == DishType.BIG_NUMBER:
            return str(value)
        elif dish_type == DishType.JSON:
            if isinstance(value, STPyV8.JSObject):
                return convert_js_json_value(value, chef)
            return value
        elif dish_type == DishType.FILE:
            return convert_js_file_value(value, chef)
        elif dish_type == DishType.LIST_FILE:
            return convert_js_file_value(value, chef)
        else:
            return value
    else:
        if isinstance(v, bytes):
            if chef is not None and hasattr(chef, "_stpyv8_context"):
                byte_list = list(v)
                byte_json = json.dumps(byte_list)
                ctx = chef._stpyv8_context
                dish = ctx.eval(f"""
                (function() {{
                    const byteArray = {byte_json};
                    const uint8 = new Uint8Array(byteArray);
                    return new module.exports.Dish(uint8.buffer, module.exports.Dish.ARRAY_BUFFER);
                }})
                """)()
                return dish
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
        input_dish = plate(input_data, chef)
    else:
        input_dish = input_data

    recipe_json = json.dumps(recipe)
    ctx = chef._stpyv8_context
    ctx.locals.input_dish = input_dish
    result = await_js_promise(ctx, f"module.exports.__piBake(input_dish, {recipe_json})")
    return plate(result, chef)  # type: ignore[return-value]



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
            split_delimiter = str(args.get("Split delimiter", "\n"))
            merge_delimiter = str(args.get("Merge delimiter", "\n"))
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
