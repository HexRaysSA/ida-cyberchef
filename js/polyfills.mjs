/**
 * Web APIs that CyberChef needs but a bare V8 isolate (mini-racer) lacks.
 *
 * V8 provides only the ECMAScript built-ins; mini-racer adds setTimeout and
 * clearTimeout. bridge.mjs imports this module first, so these globals exist
 * before any CyberChef module is evaluated.
 */

// CyberChef's operations run in a Web Worker in the web app, where the global
// object is `self`.
globalThis.self = globalThis;

// Timers. mini-racer's setTimeout throws for a zero delay, where
// Atomics.waitAsync settles synchronously and returns no promise, so replace
// it. Callbacks run from V8's task queue, which mini-racer pumps.
const pendingTimers = new Set();
let nextTimerId = 1;

globalThis.setTimeout = function(fn, delay, ...args) {
    const id = nextTimerId++;
    const callback = () => {
        if (pendingTimers.delete(id)) {
            fn(...args);
        }
    };
    pendingTimers.add(id);
    const wait = Atomics.waitAsync(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, Number(delay) || 0));
    if (wait.async) {
        wait.value.then(callback);
    } else {
        queueMicrotask(callback);
    }
    return id;
};

globalThis.clearTimeout = function(id) {
    pendingTimers.delete(id);
};

const intervals = new Map();
globalThis.setInterval = function(fn, delay, ...args) {
    const id = nextTimerId++;
    const tick = () => {
        if (intervals.has(id)) {
            intervals.set(id, setTimeout(tick, delay));
            fn(...args);
        }
    };
    intervals.set(id, setTimeout(tick, delay));
    return id;
};

globalThis.clearInterval = function(id) {
    clearTimeout(intervals.get(id));
    intervals.delete(id);
};

globalThis.setImmediate = (fn, ...args) => setTimeout(fn, 0, ...args);
globalThis.clearImmediate = clearTimeout;

globalThis.DOMException ??= class DOMException extends Error {
    constructor(message = "", name = "Error") {
        super(message);
        this.name = name;
    }
};

const timeOrigin = Date.now();
globalThis.performance ??= {timeOrigin, now: () => Date.now() - timeOrigin};

// atob/btoa per the HTML specification ("forgiving-base64").
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

globalThis.btoa = function(data) {
    data = String(data);
    if (/[^\0-\xff]/.test(data)) {
        throw new DOMException("Invalid character", "InvalidCharacterError");
    }
    let output = "";
    for (let i = 0; i < data.length; i += 3) {
        const triple = (data.charCodeAt(i) << 16) | (data.charCodeAt(i + 1) << 8) | data.charCodeAt(i + 2);
        output += BASE64[(triple >> 18) & 63] + BASE64[(triple >> 12) & 63];
        output += i + 1 < data.length ? BASE64[(triple >> 6) & 63] : "=";
        output += i + 2 < data.length ? BASE64[triple & 63] : "=";
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
    for (const char of data) {
        buffer = (buffer << 6) | BASE64.indexOf(char);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output += String.fromCharCode((buffer >> bits) & 0xff);
        }
    }
    return output;
};

// TextEncoder/TextDecoder per the WHATWG Encoding standard, for the
// encodings CyberChef uses: UTF-8, UTF-16LE/BE and latin-1.
const codeUnitsToString = function(units) {
    let output = "";
    for (let i = 0; i < units.length; i += 0x8000) {
        output += String.fromCharCode(...units.subarray(i, i + 0x8000));
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
            let codePoint = str.codePointAt(i);
            if (codePoint > 0xffff) {
                i++;
            } else if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
                codePoint = 0xfffd; // lone surrogate
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
        return {read: String(input).length, written};
    }
};

const ENCODINGS = {
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
    const invalid = function() {
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
        let needed, codePoint, lower = 0x80, upper = 0xbf;
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
            invalid();
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
            invalid();
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
    return codeUnitsToString(units.subarray(0, length));
};

globalThis.TextDecoder = class TextDecoder {
    constructor(label = "utf-8", options = {}) {
        this.encoding = ENCODINGS[String(label).trim().toLowerCase()];
        if (this.encoding === undefined) {
            throw new RangeError(`The "${label}" encoding is not supported`);
        }
        this.fatal = Boolean(options.fatal);
        this.ignoreBOM = Boolean(options.ignoreBOM);
    }

    decode(input) {
        let bytes;
        if (input === undefined || input === null) {
            bytes = new Uint8Array(0);
        } else if (ArrayBuffer.isView(input)) {
            bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        } else {
            bytes = new Uint8Array(input);
        }

        if (this.encoding === "utf-8") {
            if (!this.ignoreBOM && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
                bytes = bytes.subarray(3);
            }
            return decodeUtf8(bytes, this.fatal);
        }
        if (this.encoding === "windows-1252") {
            return codeUnitsToString(bytes);
        }

        const bigEndian = this.encoding === "utf-16be";
        if (!this.ignoreBOM && bytes.length >= 2 &&
            bytes[0] === (bigEndian ? 0xfe : 0xff) && bytes[1] === (bigEndian ? 0xff : 0xfe)) {
            bytes = bytes.subarray(2);
        }
        const units = new Uint16Array(bytes.length >> 1);
        for (let i = 0; i < units.length; i++) {
            const [a, b] = [bytes[2 * i], bytes[2 * i + 1]];
            units[i] = bigEndian ? (a << 8) | b : (b << 8) | a;
        }
        if (bytes.length % 2 && this.fatal) {
            throw new TypeError(`The encoded data was not valid for encoding ${this.encoding}`);
        }
        return codeUnitsToString(units) + (bytes.length % 2 ? "�" : "");
    }
};

// crypto.getRandomValues, backed by a ChaCha20 stream (RFC 8439 block
// function). JS cannot call into Python synchronously, so the Python side
// supplies a fresh OS-entropy key via seedRandom() before each bake.
// crypto.subtle is not provided.
const key = new Uint32Array(8);
const state = new Uint32Array(16);
const block = new Uint32Array(16);
const blockBytes = new Uint8Array(block.buffer);
let counter = 0;
let offset = 64;
let seeded = false;

const rotl = (value, shift) => (value << shift) | (value >>> (32 - shift));
const quarterRound = function(x, a, b, c, d) {
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7);
};

const nextBlock = function() {
    state.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    state.set(key, 4);
    state[12] = counter;
    state[13] = state[14] = state[15] = 0;
    block.set(state);
    for (let round = 0; round < 10; round++) {
        quarterRound(block, 0, 4, 8, 12);
        quarterRound(block, 1, 5, 9, 13);
        quarterRound(block, 2, 6, 10, 14);
        quarterRound(block, 3, 7, 11, 15);
        quarterRound(block, 0, 5, 10, 15);
        quarterRound(block, 1, 6, 11, 12);
        quarterRound(block, 2, 7, 8, 13);
        quarterRound(block, 3, 4, 9, 14);
    }
    for (let i = 0; i < 16; i++) {
        block[i] += state[i];
    }
    counter++;
    offset = 0;
};

/**
 * Key the random generator with 32 bytes given as hex.
 *
 * @param {string} seedHex
 */
export function seedRandom(seedHex) {
    for (let i = 0; i < 8; i++) {
        key[i] = parseInt(seedHex.substr(i * 8, 8), 16);
    }
    counter = 0;
    offset = 64;
    seeded = true;
}

globalThis.crypto = {
    getRandomValues(array) {
        if (!seeded) {
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
            if (offset === 64) {
                nextBlock();
            }
            bytes[i] = blockBytes[offset++];
        }
        return array;
    }
};

// Blob, File and FileReader, as far as CyberChef uses them: building files
// from parts, slicing, and reading them back as bytes or text.
const partBytes = function(part) {
    if (part instanceof Blob) {
        return part._bytes;
    }
    if (part instanceof ArrayBuffer) {
        return new Uint8Array(part);
    }
    if (ArrayBuffer.isView(part)) {
        return new Uint8Array(part.buffer, part.byteOffset, part.byteLength);
    }
    return new TextEncoder().encode(String(part));
};

globalThis.Blob = class Blob {
    constructor(parts = [], options = {}) {
        const chunks = Array.from(parts, partBytes);
        this._bytes = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
        let offset = 0;
        for (const chunk of chunks) {
            this._bytes.set(chunk, offset);
            offset += chunk.length;
        }
        this.type = String(options.type ?? "").toLowerCase();
    }

    get size() {
        return this._bytes.length;
    }

    slice(start = 0, end = this.size, type = "") {
        return new Blob([this._bytes.slice(start, end)], {type});
    }

    async arrayBuffer() {
        return this._bytes.slice().buffer;
    }

    async bytes() {
        return this._bytes.slice();
    }

    async text() {
        return new TextDecoder().decode(this._bytes);
    }
};

globalThis.File = class File extends Blob {
    constructor(parts, name, options = {}) {
        super(parts, options);
        this.name = String(name);
        this.lastModified = options.lastModified ?? Date.now();
    }
};

globalThis.FileReader = class FileReader {
    constructor() {
        this.result = null;
        this.onload = null;
        this.onerror = null;
    }

    _read(blob, convert) {
        queueMicrotask(() => {
            this.result = convert(blob._bytes);
            this.onload?.({target: this});
        });
    }

    readAsArrayBuffer(blob) {
        this._read(blob, (bytes) => bytes.slice().buffer);
    }

    readAsText(blob) {
        this._read(blob, (bytes) => new TextDecoder().decode(bytes));
    }

    readAsBinaryString(blob) {
        this._read(blob, (bytes) => codeUnitsToString(bytes));
    }
};
