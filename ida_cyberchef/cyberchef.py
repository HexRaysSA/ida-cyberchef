import json
import os
import re
from enum import IntEnum
from pathlib import Path
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

_OPERATION_SCHEMA: dict[str, Any] | None = None
_OPERATION_SCHEMA_BY_NAME: dict[str, list[dict[str, Any]]] | None = None


def _py_urandom_json(length: Any) -> str:
    """Return a JSON-encoded list of cryptographically random bytes."""
    num_bytes = int(length)
    if num_bytes < 0:
        raise ValueError("Random byte length must be non-negative")
    return json.dumps(list(os.urandom(num_bytes)))


def sanitise_operation_name(value: str) -> str:
    """Return the name form used by CyberChef's name matching."""
    return value.replace(" ", "").lower()


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
            schema_by_name.setdefault(
                sanitise_operation_name(str(operation.get("name", ""))), []
            ).append(operation)
        _OPERATION_SCHEMA_BY_NAME = schema_by_name
    return _OPERATION_SCHEMA_BY_NAME


def get_schema_operation(name: str) -> dict[str, Any] | None:
    """Return schema metadata for an operation name."""
    return get_operation_schema_by_name().get(sanitise_operation_name(name), [None])[0]


def decode_escaped_string(value: str) -> str:
    """Decode the escape sequences used in CyberChef argument defaults."""
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


def get_argument_default_value(op_name: str, arg: dict[str, Any]) -> Any:
    """Return the normalised default value for a schema argument."""
    arg_type = arg.get("type")
    value = arg.get("value")

    if arg_type in {"binaryString", "binaryShortString"} and isinstance(value, str):
        return decode_escaped_string(value)

    if arg_type == "boolean":
        return coerce_schema_boolean(value)

    if arg_type == "argSelector":
        if isinstance(value, list) and value:
            default_entry = value[get_argument_default_index(arg)]
            if isinstance(default_entry, dict):
                return default_entry.get("name", "")
            return default_entry
        return value

    if arg_type in {"editableOption", "editableOptionShort"}:
        if isinstance(value, list) and value:
            default_entry = value[get_argument_default_index(arg)]
            if isinstance(default_entry, dict):
                default_value = default_entry.get("value", default_entry.get("name", ""))
            else:
                default_value = default_entry
            if isinstance(default_value, str):
                return decode_escaped_string(default_value)
            return default_value
        return value

    if arg_type == "populateMultiOption":
        if isinstance(value, list) and value:
            default_entry = value[get_argument_default_index(arg)]
            if isinstance(default_entry, dict):
                return default_entry.get("name", "")
            return default_entry
        return value

    return value


def canonicalise_argument_name(args: list[dict[str, Any]], key: str) -> str | None:
    """Return the canonical schema argument name for a provided key."""
    sanitised_key = sanitise_operation_name(key)
    for arg in args:
        arg_name = str(arg.get("name", ""))
        if sanitise_operation_name(arg_name) == sanitised_key:
            return arg_name
    return None


def canonicalise_option_value(arg: dict[str, Any], value: Any) -> Any:
    """Resolve display names to the values expected by the runtime."""
    if not isinstance(value, str):
        return value

    options = arg.get("value")
    if not isinstance(options, list):
        return value

    for option in options:
        if isinstance(option, dict):
            option_name = str(option.get("name", ""))
            option_value = option.get("value", option_name)
            if sanitise_operation_name(option_name) == sanitise_operation_name(value):
                if isinstance(option_value, str):
                    return decode_escaped_string(option_value)
                return option_value
            if isinstance(option_value, str) and option_value == value:
                return decode_escaped_string(option_value)
        elif sanitise_operation_name(str(option)) == sanitise_operation_name(value):
            return option

    return value


def expand_populate_multi_option(arg: dict[str, Any], value: Any) -> dict[str, Any]:
    """Expand populateMultiOption selections into their target arguments."""
    if not isinstance(value, str):
        return {}

    options = arg.get("value")
    targets = arg.get("target")
    if not isinstance(options, list) or not isinstance(targets, list):
        return {}

    for option in options:
        if not isinstance(option, dict):
            continue
        option_name = str(option.get("name", ""))
        if sanitise_operation_name(option_name) != sanitise_operation_name(value):
            continue
        expanded_values = option.get("value", [])
        if not isinstance(expanded_values, list):
            return {}
        return {
            str(target_index): expanded_values[index]
            for index, target_index in enumerate(targets)
            if index < len(expanded_values)
        }

    return {}


def normalise_recipe_argument_value(op_name: str, arg: dict[str, Any], value: Any) -> Any:
    """Return a recipe argument value in the form CyberChef expects."""
    arg_type = arg.get("type")

    if arg_type in {"binaryString", "binaryShortString"} and isinstance(value, str):
        return decode_escaped_string(value)

    if arg_type == "boolean":
        return coerce_schema_boolean(value)

    if arg_type == "number" and isinstance(value, str):
        try:
            return int(value) if "." not in value else float(value)
        except ValueError:
            return value

    if arg_type in {"option", "editableOption", "editableOptionShort", "argSelector", "populateMultiOption"}:
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
            normalised_args[arg_name] = normalise_recipe_argument_value(
                name, arg, provided_by_name[arg_name]
            )
            continue
        if arg_name in populate_expansions:
            normalised_args[arg_name] = normalise_recipe_argument_value(
                name, arg, populate_expansions[arg_name]
            )
            continue
        if should_apply_schema_default(arg):
            normalised_args[arg_name] = get_argument_default_value(name, arg)

    if not normalised_args:
        return name

    return {"op": name, "args": normalised_args}


def normalise_js_recipe(recipe: list[str | RecipeOperation]) -> list[str | RecipeOperation]:
    """Return a JS-backed recipe with bridge-compatible argument defaults."""
    return [normalise_js_recipe_operation(operation) for operation in recipe]


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
        ctx.eval("globalThis.__piDrainTimers && globalThis.__piDrainTimers()")
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
        path = str(Path(__file__).parent / "data" / "CyberChef.js")
    ctx = STPyV8.JSContext()
    ctx.enter()
    ctx.locals.py_urandom_json = _py_urandom_json

    # Setup minimal global environment for CyberChef
    ctx.eval("""
    globalThis.global = globalThis;
    globalThis.window = globalThis;
    globalThis.self = globalThis;
    globalThis.document = {};
    globalThis.app = {
        alert: function() {}
    };

    globalThis.__piNextTicks = [];
    globalThis.__piTimers = [];
    globalThis.__piTimerId = 1;
    globalThis.__piSchedule = function(queue, fn, args) {
        const id = globalThis.__piTimerId++;
        queue.push({id: id, fn: fn, args: args});
        return id;
    };
    globalThis.__piCancel = function(queue, id) {
        for (let i = 0; i < queue.length; i++) {
            if (queue[i].id === id) {
                queue.splice(i, 1);
                return;
            }
        }
    };
    globalThis.__piDrainTimers = function() {
        while (globalThis.__piNextTicks.length || globalThis.__piTimers.length) {
            const nextTicks = globalThis.__piNextTicks.splice(0, globalThis.__piNextTicks.length);
            for (const entry of nextTicks) {
                entry.fn.apply(globalThis, entry.args);
            }
            const timers = globalThis.__piTimers.splice(0, globalThis.__piTimers.length);
            for (const entry of timers) {
                entry.fn.apply(globalThis, entry.args);
            }
        }
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
            return globalThis.__piSchedule(globalThis.__piNextTicks, fn, args);
        }
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
        const args = Array.prototype.slice.call(arguments, 2);
        return globalThis.__piSchedule(globalThis.__piTimers, fn, args);
    };
    globalThis.setInterval = function(fn, ms) {
        const args = Array.prototype.slice.call(arguments, 2);
        return globalThis.__piSchedule(globalThis.__piTimers, fn, args);
    };
    globalThis.setImmediate = function(fn) {
        const args = Array.prototype.slice.call(arguments, 1);
        return globalThis.__piSchedule(globalThis.__piNextTicks, fn, args);
    };
    globalThis.clearTimeout = function(id) {
        globalThis.__piCancel(globalThis.__piTimers, id);
    };
    globalThis.clearInterval = function(id) {
        globalThis.__piCancel(globalThis.__piTimers, id);
    };
    globalThis.clearImmediate = function(id) {
        globalThis.__piCancel(globalThis.__piNextTicks, id);
    };
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
        chef: Optional CyberChef module for creating proper Dish instances from bytes

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
    ctx = chef._stpyv8_context

    if isinstance(input_data, bytes):
        input_expression = "input_dish"
        ctx.locals.input_dish = plate(input_data, chef)
    else:
        input_expression = json.dumps(input_data)

    normalised_recipe = normalise_js_recipe(recipe)
    recipe_json = json.dumps(normalised_recipe)
    result = await_js_promise(ctx, f"module.exports.__piBake({input_expression}, {recipe_json})")
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
