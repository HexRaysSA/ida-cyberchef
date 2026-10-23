// Runtime environment for CyberChef.js inside a bare V8 isolate (mini-racer).
//
// V8 provides only ECMAScript built-ins, plus setTimeout/clearTimeout that
// mini-racer installs. This file adds the small set of browser/Node.js APIs
// that CyberChef's Node-targeted bundle expects, and the `__pi*` helpers the
// Python bridge (ida_cyberchef/cyberchef.py) calls. It is evaluated once,
// before the bundle.
//
// Python calls into JS only with primitive values (and handles to JS objects
// it previously received), so binary data crosses the boundary as latin-1
// strings (Python to JS) and ArrayBuffers (JS to Python), and structured data
// as JSON text.

(function() {
    "use strict";

    globalThis.global = globalThis;
    globalThis.window = globalThis;
    globalThis.self = globalThis;
    globalThis.document = {};
    globalThis.app = {
        alert: function() {}
    };

    // Minimal process polyfill
    globalThis.process = {
        platform: "linux",
        env: {},
        cwd: () => "/",
        version: "v18.0.0",
        versions: {node: "v18.0.0"},
        nextTick: function(fn, ...args) {
            Promise.resolve().then(() => fn.apply(globalThis, args));
        }
    };

    // Timers. mini-racer's own setTimeout breaks for a zero delay, where
    // Atomics.waitAsync settles synchronously and returns no promise, so
    // replace it. Timer callbacks run from V8's task queue, which mini-racer
    // pumps on its own thread.
    const pendingTimers = new Set();
    let nextTimerId = 1;
    globalThis.setTimeout = function(fn, delay, ...args) {
        const id = nextTimerId++;
        const callback = () => {
            if (pendingTimers.delete(id)) {
                fn.apply(globalThis, args);
            }
        };
        pendingTimers.add(id);
        const view = new Int32Array(new SharedArrayBuffer(4));
        const wait = Atomics.waitAsync(view, 0, 0, Math.max(0, Number(delay) || 0));
        if (wait.async) {
            wait.value.then(callback);
        } else {
            Promise.resolve().then(callback);
        }
        return id;
    };
    globalThis.clearTimeout = function(id) {
        pendingTimers.delete(id);
    };

    globalThis.queueMicrotask = function(fn) {
        Promise.resolve().then(() => fn());
    };

    globalThis.setImmediate = function(fn, ...args) {
        return setTimeout(() => fn.apply(globalThis, args), 0);
    };
    globalThis.clearImmediate = function(id) {
        clearTimeout(id);
    };

    const intervals = new Map();
    let nextIntervalId = 1;
    globalThis.setInterval = function(fn, delay, ...args) {
        const id = nextIntervalId++;
        const tick = () => {
            if (!intervals.has(id)) {
                return;
            }
            intervals.set(id, setTimeout(tick, delay));
            fn.apply(globalThis, args);
        };
        intervals.set(id, setTimeout(tick, delay));
        return id;
    };
    globalThis.clearInterval = function(id) {
        const timeoutId = intervals.get(id);
        intervals.delete(id);
        if (timeoutId !== undefined) {
            clearTimeout(timeoutId);
        }
    };

    if (typeof DOMException === "undefined") {
        globalThis.DOMException = class DOMException extends Error {
            constructor(message = "", name = "Error") {
                super(message);
                this.name = name;
            }
        };
    }

    // atob/btoa per the HTML specification ("forgiving-base64").
    const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_LOOKUP = new Int16Array(128).fill(-1);
    for (let i = 0; i < BASE64_ALPHABET.length; i++) {
        BASE64_LOOKUP[BASE64_ALPHABET.charCodeAt(i)] = i;
    }

    globalThis.btoa = function(data) {
        data = String(data);
        let output = "";
        for (let i = 0; i < data.length; i += 3) {
            const a = data.charCodeAt(i);
            const b = i + 1 < data.length ? data.charCodeAt(i + 1) : 0;
            const c = i + 2 < data.length ? data.charCodeAt(i + 2) : 0;
            if (a > 0xff || b > 0xff || c > 0xff) {
                throw new DOMException("Invalid character", "InvalidCharacterError");
            }
            const triple = (a << 16) | (b << 8) | c;
            output += BASE64_ALPHABET[(triple >> 18) & 0x3f] + BASE64_ALPHABET[(triple >> 12) & 0x3f];
            output += i + 1 < data.length ? BASE64_ALPHABET[(triple >> 6) & 0x3f] : "=";
            output += i + 2 < data.length ? BASE64_ALPHABET[triple & 0x3f] : "=";
        }
        return output;
    };

    globalThis.atob = function(data) {
        data = String(data).replace(/[\t\n\f\r ]/g, "");
        if (data.length % 4 === 0) {
            data = data.replace(/==?$/, "");
        }
        if (data.length % 4 === 1 || /[^A-Za-z0-9+/]/.test(data)) {
            throw new DOMException("The string to be decoded is not correctly encoded.", "InvalidCharacterError");
        }
        let output = "";
        let buffer = 0;
        let bits = 0;
        for (let i = 0; i < data.length; i++) {
            buffer = (buffer << 6) | BASE64_LOOKUP[data.charCodeAt(i)];
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                output += String.fromCharCode((buffer >> bits) & 0xff);
            }
        }
        return output;
    };

    // TextEncoder/TextDecoder per the WHATWG Encoding standard, for the
    // encodings CyberChef asks for: UTF-8, UTF-16LE/BE and latin-1.
    const bytesToString = function(codeUnits) {
        let output = "";
        for (let i = 0; i < codeUnits.length; i += 0x8000) {
            output += String.fromCharCode.apply(null, codeUnits.subarray(i, i + 0x8000));
        }
        return output;
    };

    globalThis.TextEncoder = class TextEncoder {
        get encoding() {
            return "utf-8";
        }

        encode(input = "") {
            const str = String(input);
            const output = new Uint8Array(str.length * 3);
            let length = 0;
            for (let i = 0; i < str.length; i++) {
                let codePoint = str.charCodeAt(i);
                if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < str.length) {
                    const next = str.charCodeAt(i + 1);
                    if (next >= 0xdc00 && next <= 0xdfff) {
                        codePoint = 0x10000 + ((codePoint - 0xd800) << 10) + (next - 0xdc00);
                        i++;
                    }
                }
                if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
                    codePoint = 0xfffd;
                }
                if (codePoint < 0x80) {
                    output[length++] = codePoint;
                } else if (codePoint < 0x800) {
                    output[length++] = 0xc0 | (codePoint >> 6);
                    output[length++] = 0x80 | (codePoint & 0x3f);
                } else if (codePoint < 0x10000) {
                    output[length++] = 0xe0 | (codePoint >> 12);
                    output[length++] = 0x80 | ((codePoint >> 6) & 0x3f);
                    output[length++] = 0x80 | (codePoint & 0x3f);
                } else {
                    output[length++] = 0xf0 | (codePoint >> 18);
                    output[length++] = 0x80 | ((codePoint >> 12) & 0x3f);
                    output[length++] = 0x80 | ((codePoint >> 6) & 0x3f);
                    output[length++] = 0x80 | (codePoint & 0x3f);
                }
            }
            return output.slice(0, length);
        }

        encodeInto(input, destination) {
            const encoded = this.encode(input);
            const written = Math.min(encoded.length, destination.length);
            destination.set(encoded.subarray(0, written));
            return {read: String(input).length, written: written};
        }
    };

    const ENCODING_LABELS = {
        "utf-8": "utf-8",
        "utf8": "utf-8",
        "unicode-1-1-utf-8": "utf-8",
        "utf-16": "utf-16le",
        "utf-16le": "utf-16le",
        "utf-16be": "utf-16be",
        "latin1": "windows-1252",
        "iso-8859-1": "windows-1252",
        "ascii": "windows-1252",
        "us-ascii": "windows-1252",
        "windows-1252": "windows-1252",
    };

    const decodeUtf8 = function(bytes, fatal) {
        const units = new Uint16Array(bytes.length);
        let length = 0;
        let i = 0;
        const fail = function() {
            if (fatal) {
                throw new TypeError("The encoded data was not valid for encoding utf-8");
            }
            units[length++] = 0xfffd;
        };
        while (i < bytes.length) {
            const first = bytes[i];
            if (first < 0x80) {
                units[length++] = first;
                i++;
                continue;
            }
            let needed = 0;
            let codePoint = 0;
            let lower = 0x80;
            let upper = 0xbf;
            if (first >= 0xc2 && first <= 0xdf) {
                needed = 1;
                codePoint = first & 0x1f;
            } else if (first >= 0xe0 && first <= 0xef) {
                needed = 2;
                codePoint = first & 0x0f;
                if (first === 0xe0) lower = 0xa0;
                if (first === 0xed) upper = 0x9f;
            } else if (first >= 0xf0 && first <= 0xf4) {
                needed = 3;
                codePoint = first & 0x07;
                if (first === 0xf0) lower = 0x90;
                if (first === 0xf4) upper = 0x8f;
            } else {
                fail();
                i++;
                continue;
            }
            let j = 1;
            for (; j <= needed; j++) {
                const next = bytes[i + j];
                if (i + j >= bytes.length || next < lower || next > upper) {
                    break;
                }
                codePoint = (codePoint << 6) | (next & 0x3f);
                lower = 0x80;
                upper = 0xbf;
            }
            if (j <= needed) {
                // Invalid or truncated sequence: replace the maximal subpart.
                fail();
                i += j;
                continue;
            }
            i += needed + 1;
            if (codePoint >= 0x10000) {
                codePoint -= 0x10000;
                units[length++] = 0xd800 + (codePoint >> 10);
                units[length++] = 0xdc00 + (codePoint & 0x3ff);
            } else {
                units[length++] = codePoint;
            }
        }
        return bytesToString(units.subarray(0, length));
    };

    const decodeUtf16 = function(bytes, bigEndian, fatal) {
        const units = new Uint16Array(bytes.length >> 1);
        for (let i = 0; i < units.length; i++) {
            const a = bytes[2 * i];
            const b = bytes[2 * i + 1];
            units[i] = bigEndian ? (a << 8) | b : (b << 8) | a;
        }
        let output = bytesToString(units);
        if (bytes.length % 2) {
            if (fatal) {
                throw new TypeError("The encoded data was not valid for encoding utf-16");
            }
            output += "�";
        }
        return output;
    };

    globalThis.TextDecoder = class TextDecoder {
        constructor(label = "utf-8", options = {}) {
            const encoding = ENCODING_LABELS[String(label).trim().toLowerCase()];
            if (encoding === undefined) {
                throw new RangeError("The \"" + label + "\" encoding is not supported");
            }
            this._encoding = encoding;
            this._fatal = Boolean(options && options.fatal);
            this._ignoreBOM = Boolean(options && options.ignoreBOM);
        }

        get encoding() {
            return this._encoding;
        }

        get fatal() {
            return this._fatal;
        }

        get ignoreBOM() {
            return this._ignoreBOM;
        }

        decode(input) {
            let bytes;
            if (input === undefined || input === null) {
                bytes = new Uint8Array(0);
            } else if (input instanceof ArrayBuffer) {
                bytes = new Uint8Array(input);
            } else if (ArrayBuffer.isView(input)) {
                bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
            } else {
                bytes = Uint8Array.from(input);
            }

            if (this._encoding === "utf-8") {
                if (!this._ignoreBOM && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
                    bytes = bytes.subarray(3);
                }
                return decodeUtf8(bytes, this._fatal);
            }
            if (this._encoding === "utf-16le" || this._encoding === "utf-16be") {
                const bigEndian = this._encoding === "utf-16be";
                if (!this._ignoreBOM && bytes.length >= 2 &&
                    bytes[0] === (bigEndian ? 0xfe : 0xff) && bytes[1] === (bigEndian ? 0xff : 0xfe)) {
                    bytes = bytes.subarray(2);
                }
                return decodeUtf16(bytes, bigEndian, this._fatal);
            }
            return bytesToString(bytes);
        }
    };

    if (!Uint8Array.prototype.concat) {
        Uint8Array.prototype.concat = function(...values) {
            const output = Array.from(this);
            for (const value of values) {
                if (ArrayBuffer.isView(value)) {
                    output.push(...Array.from(value));
                } else if (Array.isArray(value)) {
                    output.push(...value);
                } else {
                    output.push(value);
                }
            }
            return output;
        };
    }

    // crypto.getRandomValues, backed by a ChaCha20 stream (RFC 8439 block
    // function) keyed with OS entropy that the Python bridge supplies via
    // __piSeedRandom. JS cannot call back into Python synchronously, so the
    // key is refreshed on every bake instead. crypto.subtle is unavailable.
    const chachaKey = new Uint32Array(8);
    const chachaState = new Uint32Array(16);
    const chachaBlock = new Uint32Array(16);
    const chachaBytes = new Uint8Array(chachaBlock.buffer);
    let chachaCounter = 0;
    let chachaOffset = 64;
    let chachaSeeded = false;

    const rotl = (value, shift) => (value << shift) | (value >>> (32 - shift));
    const quarterRound = function(x, a, b, c, d) {
        x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
    };

    const refillChaCha = function() {
        chachaState[0] = 0x61707865;
        chachaState[1] = 0x3320646e;
        chachaState[2] = 0x79622d32;
        chachaState[3] = 0x6b206574;
        chachaState.set(chachaKey, 4);
        chachaState[12] = chachaCounter >>> 0;
        chachaState[13] = Math.floor(chachaCounter / 0x100000000) >>> 0;
        chachaState[14] = 0;
        chachaState[15] = 0;
        chachaBlock.set(chachaState);
        for (let round = 0; round < 10; round++) {
            quarterRound(chachaBlock, 0, 4, 8, 12);
            quarterRound(chachaBlock, 1, 5, 9, 13);
            quarterRound(chachaBlock, 2, 6, 10, 14);
            quarterRound(chachaBlock, 3, 7, 11, 15);
            quarterRound(chachaBlock, 0, 5, 10, 15);
            quarterRound(chachaBlock, 1, 6, 11, 12);
            quarterRound(chachaBlock, 2, 7, 8, 13);
            quarterRound(chachaBlock, 3, 4, 9, 14);
        }
        for (let i = 0; i < 16; i++) {
            chachaBlock[i] += chachaState[i];
        }
        chachaCounter++;
        chachaOffset = 0;
    };

    globalThis.__piSeedRandom = function(seedHex) {
        for (let i = 0; i < 8; i++) {
            chachaKey[i] = parseInt(seedHex.substr(i * 8, 8), 16);
        }
        chachaCounter = 0;
        chachaOffset = 64;
        chachaSeeded = true;
    };

    globalThis.crypto = {
        getRandomValues: function(array) {
            if (!chachaSeeded) {
                throw new Error("crypto.getRandomValues used before the random generator was seeded");
            }
            if (!ArrayBuffer.isView(array) || array instanceof Float32Array || array instanceof Float64Array) {
                throw new TypeError("crypto.getRandomValues requires an integer typed array");
            }
            if (array.byteLength > 65536) {
                throw new DOMException("The requested length exceeds 65,536 bytes", "QuotaExceededError");
            }
            const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
            for (let i = 0; i < bytes.length; i++) {
                if (chachaOffset === 64) {
                    refillChaCha();
                }
                bytes[i] = chachaBytes[chachaOffset++];
            }
            return array;
        }
    };

    const timeOrigin = Date.now();
    globalThis.performance = {
        timeOrigin: timeOrigin,
        now: function() {
            return Date.now() - timeOrigin;
        }
    };

    // Setup minimal CommonJS environment
    globalThis.module = {exports: {}};

    // ------------------------------------------------------------------
    // Helpers called by the Python bridge.
    // ------------------------------------------------------------------

    const describeError = function(error) {
        if (error instanceof Error) {
            return String(error);
        }
        if (typeof error === "string") {
            return error;
        }
        try {
            const json = JSON.stringify(error);
            if (json !== undefined) {
                return json;
            }
        } catch (jsonError) {
            // fall through
        }
        return String(error);
    };

    // Invoke fn(...args), always returning a promise. A failure rejects with
    // a plain "Name: message" string, so Python can report it without a JS
    // stack trace or source excerpt.
    globalThis.__piCall = async function(fn, ...args) {
        try {
            return await fn(...args);
        } catch (error) {
            throw describeError(error);
        }
    };

    const latin1ToBytes = function(latin1) {
        const bytes = new Uint8Array(latin1.length);
        for (let i = 0; i < latin1.length; i++) {
            bytes[i] = latin1.charCodeAt(i);
        }
        return bytes;
    };

    globalThis.__piBytes = function(latin1) {
        return latin1ToBytes(latin1).buffer;
    };

    globalThis.__piJson = function(json) {
        return JSON.parse(json);
    };

    globalThis.__piMakeBytesDish = function(latin1) {
        return new module.exports.Dish(latin1ToBytes(latin1).buffer, module.exports.Dish.ARRAY_BUFFER);
    };

    const NON_OPERATION_EXPORTS = [
        "bake",
        "help",
        "register",
        "Dish",
        "DishError",
        "OperationError",
        "ExcludedOperationError",
    ];

    const sanitise = function(value) {
        return value.replace(/ /g, "").toLowerCase();
    };

    globalThis.__piBake = async function(input, recipeJson, seedHex) {
        __piSeedRandom(seedHex);
        const recipeConfig = JSON.parse(recipeJson);
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
                    !NON_OPERATION_EXPORTS.includes(candidateName) &&
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

    const isDishType = (type) => typeof type === "number" && Number.isInteger(type) && type >= 0 && type <= 8;

    const toArrayBuffer = function(value) {
        if (value instanceof ArrayBuffer) {
            return value;
        }
        if (ArrayBuffer.isView(value)) {
            return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
        }
        return Uint8Array.from(value).buffer;
    };

    const isByteList = function(value) {
        if (ArrayBuffer.isView(value)) {
            return true;
        }
        if (!Array.isArray(value)) {
            return false;
        }
        return value.every((b) => typeof b === "number" && Number.isInteger(b) && b >= 0 && b <= 0xff);
    };

    const fileToParts = function(file) {
        return {
            meta: {
                name: file && file.name ? String(file.name) : "",
                type: file && file.type ? String(file.type) : "",
            },
            data: file && file.data ? new Uint8Array(toArrayBuffer(file.data)) : new Uint8Array(0),
        };
    };

    // Convert a JS value into a [kind, payload, extra] array for plate():
    //   ["dish", type, value]  value is an ArrayBuffer, string, number, JSON
    //                          text, or (for files) [JSON metadata, ArrayBuffer]
    //   ["json", JSON text]    for any other JSON-serialisable value
    //   ["string", text]       otherwise
    globalThis.__piExport = function(value) {
        if (value !== null && typeof value === "object" && "value" in value && "type" in value &&
            isDishType(value.type)) {
            const type = value.type;
            const dishValue = value.value;
            switch (type) {
                case 0: // BYTE_ARRAY
                    if (isByteList(dishValue)) {
                        return ["dish", type, toArrayBuffer(dishValue)];
                    }
                    // Not plain bytes (e.g. NaN from a failed parse): hand back the
                    // values themselves so Python reports the conversion error.
                    return ["dish", type, Array.isArray(dishValue) ? dishValue : String(dishValue)];
                case 1: // STRING
                case 3: // HTML
                    return ["dish", type, String(dishValue)];
                case 2: // NUMBER
                    return ["dish", type, Number(dishValue)];
                case 4: // ARRAY_BUFFER
                    if (dishValue instanceof ArrayBuffer || ArrayBuffer.isView(dishValue) || isByteList(dishValue)) {
                        return ["dish", type, toArrayBuffer(dishValue)];
                    }
                    return ["dish", type, String(dishValue)];
                case 5: // BIG_NUMBER
                    return ["dish", type, String(dishValue)];
                case 6: { // JSON
                    const json = JSON.stringify(dishValue);
                    return ["dish", type, json === undefined ? "null" : json];
                }
                case 7: // FILE
                case 8: { // LIST_FILE
                    const files = Array.isArray(dishValue) ? dishValue : [dishValue];
                    const parts = files.map(fileToParts);
                    const total = parts.reduce((sum, part) => sum + part.data.length, 0);
                    const data = new Uint8Array(total);
                    let offset = 0;
                    const meta = parts.map(function(part) {
                        data.set(part.data, offset);
                        offset += part.data.length;
                        return Object.assign({length: part.data.length}, part.meta);
                    });
                    return ["dish", type, [JSON.stringify({list: Array.isArray(dishValue), files: meta}), data.buffer]];
                }
            }
        }
        if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
            return ["bytes", toArrayBuffer(value)];
        }
        try {
            const json = JSON.stringify(value);
            if (json !== undefined) {
                return ["json", json];
            }
        } catch (error) {
            // fall through
        }
        return ["string", String(value)];
    };
})();
