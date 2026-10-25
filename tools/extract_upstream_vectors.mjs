/**
 * Extract CyberChef's own operation tests as test vectors for ida-cyberchef.
 *
 * Imports every file in deps/CyberChef/tests/operations/tests/, which register
 * their cases with TestRegister, and writes them to
 * tests/data/cyberchef_test_vectors.json for tests/test_cyberchef_vectors.py.
 * Recipes keep CyberChef's positional args, which bake() accepts as is.
 *
 * Usage (see `just test-vectors`): node tools/extract_upstream_vectors.mjs
 * Needs CyberChef's npm dependencies and generated config (`just config`).
 */

import fs from "node:fs";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cyberchef = path.join(root, "deps", "CyberChef");
const testsDir = path.join(cyberchef, "tests", "operations", "tests");
const outputPath = path.join(root, "tests", "data", "cyberchef_test_vectors.json");

const {default: TestRegister} = await import(pathToFileURL(path.join(cyberchef, "tests", "lib", "TestRegister.mjs")));

const exactVectors = [];
const matchVectors = [];

for (const file of fs.readdirSync(testsDir).filter((name) => name.endsWith(".mjs")).sort()) {
    const before = TestRegister.tests.length;
    await import(pathToFileURL(path.join(testsDir, file)));
    const module = path.basename(file, ".mjs");

    for (const test of TestRegister.tests.slice(before)) {
        const vector = {name: test.name, module, input: test.input, recipe: test.recipeConfig};
        if ("expectedMatch" in test) {
            matchVectors.push({...vector, expected_match: test.expectedMatch.source, flags: test.expectedMatch.flags});
        } else if ("unexpectedMatch" in test) {
            matchVectors.push({
                ...vector,
                unexpected_match: test.unexpectedMatch.source,
                flags: test.unexpectedMatch.flags,
            });
        } else {
            exactVectors.push({...vector, expected: test.expectedOutput, expected_error: Boolean(test.expectedError)});
        }
    }
}

fs.writeFileSync(outputPath, JSON.stringify({exact_vectors: exactVectors, match_vectors: matchVectors}, null, 1) + "\n");
console.log(`Wrote ${exactVectors.length} exact and ${matchVectors.length} match vectors to ${path.relative(root, outputPath)}`);
// Some test modules leave handles open (timers, workers).
process.exit(0);
