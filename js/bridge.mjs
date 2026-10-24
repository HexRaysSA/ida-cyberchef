/**
 * Entry point of the CyberChef bundle that ida_cyberchef runs in V8.
 *
 * It exposes `globalThis.cyberchef.bake()`, which runs a recipe through
 * CyberChef's core Recipe class, the same engine the web app uses, so flow
 * control (Fork, Jump, Register, ...) and argument handling match upstream.
 *
 * Python passes only strings and numbers in, and gets back primitives and
 * ArrayBuffers, so bytes travel as latin-1 strings into JS and as
 * ArrayBuffers out, and structured data as JSON text.
 */

// Must stay the first import: it installs globals CyberChef needs at load time.
import {seedRandom} from "./polyfills.mjs";
import Dish from "../deps/CyberChef/src/core/Dish.mjs";
import Recipe from "../deps/CyberChef/src/core/Recipe.mjs";
import {detectFileType} from "../deps/CyberChef/src/core/lib/FileType.mjs";
import OperationConfig from "../deps/CyberChef/src/core/config/OperationConfig.json" with {type: "json"};

const sanitise = (name) => String(name).replace(/ /g, "").toLowerCase();
const isSubheading = (label) => /^\[\/?[a-z0-9 \-()^]+\]$/i.test(label);

const OPERATION_NAMES = new Map(Object.keys(OperationConfig).map((name) => [sanitise(name), name]));

const optionLabel = (option) => (typeof option === "string" ? option : option.name);
// A few editableOption presets are plain strings rather than {name, value}.
const optionValue = (option) => (typeof option === "string" ? option : option.value);

/**
 * The selectable entries of an option-like argument, without subheadings.
 */
const choices = (arg) => arg.value.filter((option) => !isSubheading(optionLabel(option)));

const findChoice = (arg, label) => choices(arg).find((option) => sanitise(optionLabel(option)) === sanitise(label));

const toBoolean = (value) => (typeof value === "string" ? value.trim().toLowerCase() === "true" : Boolean(value));

/**
 * The value the web app's recipe editor uses for an argument the user did not set.
 */
function defaultValue(arg) {
    switch (arg.type) {
        case "option":
        case "argSelector":
        case "populateOption":
        case "populateMultiOption": {
            const preferred = arg.value[arg.defaultIndex ?? 0];
            return optionLabel(preferred && !isSubheading(optionLabel(preferred)) ? preferred : choices(arg)[0]);
        }
        case "editableOption":
        case "editableOptionShort":
            return optionValue(arg.value[arg.defaultIndex ?? 0]);
        case "toggleString":
            return {string: arg.value, option: arg.toggleValues[0]};
        case "boolean":
            // Some configs give "false" as a string, which would be truthy.
            return toBoolean(arg.value);
        default:
            return arg.value;
    }
}

/**
 * Convert a user-supplied argument value to the form the recipe editor produces.
 * Core CyberChef then decodes escapes and parses numbers (Ingredient.prepare).
 */
function givenValue(arg, value) {
    switch (arg.type) {
        case "option":
        case "argSelector":
        case "populateOption":
        case "populateMultiOption": {
            const choice = typeof value === "string" && findChoice(arg, value);
            return choice ? optionLabel(choice) : value;
        }
        case "editableOption":
        case "editableOptionShort": {
            // Accept a preset's label ("Line feed") as well as its value ("\\n").
            const choice = typeof value === "string" && findChoice(arg, value);
            return choice ? optionValue(choice) : value;
        }
        case "toggleString":
            if (value !== null && typeof value === "object") {
                return {string: value.string ?? "", option: value.option ?? arg.toggleValues[0]};
            }
            return {string: String(value), option: arg.toggleValues[0]};
        case "boolean":
            return toBoolean(value);
        default:
            return value;
    }
}

/**
 * Turn {op, args} with arguments keyed by name into core's positional form.
 * Positional args (as in recipes exported from the web app) pass through.
 */
function toIngredient(entry) {
    const {op, args = {}} = typeof entry === "string" ? {op: entry} : entry;
    const name = OPERATION_NAMES.get(sanitise(op));
    if (name === undefined) {
        throw new Error(`Couldn't find an operation with name '${op}'.`);
    }
    if (Array.isArray(args)) {
        return {op: name, args};
    }

    const argConfig = OperationConfig[name].args;
    const given = new Map(Object.entries(args).map(([key, value]) => [sanitise(key), value]));
    const values = argConfig.map((arg) =>
        given.has(sanitise(arg.name)) ? givenValue(arg, given.get(sanitise(arg.name))) : defaultValue(arg)
    );

    // Choosing a preset fills in its target arguments, as in the web app,
    // unless they were given explicitly.
    argConfig.forEach((arg, index) => {
        if (!arg.type.startsWith("populate") || !given.has(sanitise(arg.name))) {
            return;
        }
        const choice = findChoice(arg, values[index]);
        if (!choice) {
            return;
        }
        const targets = arg.type === "populateMultiOption" ? arg.target : [arg.target];
        const presets = arg.type === "populateMultiOption" ? optionValue(choice) : [optionValue(choice)];
        targets.forEach((target, i) => {
            if (!given.has(sanitise(argConfig[target].name)) && !(arg.type === "populateOption" && presets[i] === "")) {
                values[target] = presets[i];
            }
        });
    });

    return {op: name, args: values};
}

function latin1ToArrayBuffer(latin1) {
    const bytes = new Uint8Array(latin1.length);
    for (let i = 0; i < latin1.length; i++) {
        bytes[i] = latin1.charCodeAt(i);
    }
    return bytes.buffer;
}

function toArrayBuffer(value) {
    if (value instanceof ArrayBuffer) {
        return value;
    }
    if (ArrayBuffer.isView(value)) {
        return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
    }
    return Uint8Array.from(value).buffer;
}

/**
 * Convert the final dish to [type, payload] for Python. Files become
 * [type, [metadata JSON, concatenated contents]].
 */
function exportDish(dish) {
    const {type, value} = dish;
    switch (type) {
        case Dish.BYTE_ARRAY:
        case Dish.ARRAY_BUFFER:
            return [type, toArrayBuffer(value)];
        case Dish.NUMBER:
            return [type, Number(value)];
        case Dish.JSON:
            return [type, JSON.stringify(value) ?? "null"];
        case Dish.FILE:
        case Dish.LIST_FILE: {
            const files = (type === Dish.FILE ? [value] : value).map((file) => ({
                name: String(file.name ?? ""),
                // Most operations leave the type empty; report the detected one.
                type: file.type || detectFileType(file._bytes)[0]?.mime || "application/unknown",
                data: file._bytes,
            }));
            const data = new Uint8Array(files.reduce((total, file) => total + file.data.length, 0));
            let offset = 0;
            for (const file of files) {
                data.set(file.data, offset);
                offset += file.data.length;
            }
            const meta = files.map(({name, type, data}) => ({name, type, length: data.length}));
            return [type, [JSON.stringify(meta), data.buffer]];
        }
        default: // STRING, HTML, BIG_NUMBER
            return [type, String(value)];
    }
}

function describeError(error) {
    if (error instanceof Error) {
        return String(error);
    }
    if (error !== null && typeof error === "object" && "message" in error) {
        return String(error.message);
    }
    return String(error);
}

/**
 * Run a recipe.
 *
 * @param {string} input - text, or bytes as a latin-1 string when isBytes
 * @param {boolean} isBytes
 * @param {string} recipeJson - [opName | {op, args}], args keyed by name or positional
 * @param {string} seedHex - 32 bytes of OS entropy for crypto.getRandomValues
 * @returns {Promise<Array>} [dish type, payload]; rejects with an error message string
 */
async function bake(input, isBytes, recipeJson, seedHex) {
    seedRandom(seedHex);
    try {
        const recipe = new Recipe(JSON.parse(recipeJson).map(toIngredient));
        const dish = isBytes ? new Dish(latin1ToArrayBuffer(input), Dish.ARRAY_BUFFER) : new Dish(input, Dish.STRING);
        const progress = await recipe.execute(dish);
        if (progress < recipe.opList.length) {
            // Core reports an OperationError by replacing the dish with its message.
            throw String(dish.value);
        }
        return exportDish(dish);
    } catch (error) {
        throw describeError(error);
    }
}

globalThis.cyberchef = {bake, seedRandom};
