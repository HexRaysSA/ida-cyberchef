import json
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


class RecipeOperation(TypedDict, total=False):
    """CyberChef recipe operation structure.

    Either a string operation name or a dict with op and args.
    """

    op: str
    args: dict[str, Any]


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

    return source.replace(_NODE_API_SYNC_WRAPPER_OLD, _NODE_API_SYNC_WRAPPER_NEW, 1)


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
            return value
        elif dish_type in (DishType.FILE, DishType.LIST_FILE):
            return value
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


def bake(input_data: bytes | str, recipe: list[str | RecipeOperation]) -> bytes | str:
    """Execute CyberChef operations using the loaded JS runtime.

    Args:
        input_data: Input data as bytes or string
        recipe: List of operations. Each operation is either:
            - A string operation name: "To Base64"
            - A dict with op and args: {"op": "SHA2", "args": {"size": 256}}

    Returns: Result as bytes or string depending on the final operation output
    """
    if not recipe:
        return input_data

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
