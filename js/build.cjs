/**
 * Builds ida_cyberchef/data/CyberChef.js: CyberChef's core (all operations),
 * the polyfills and the bridge, as one script for a bare V8 isolate.
 *
 * Usage (see `just build`): node js/build.cjs
 * webpack and the npm dependencies come from deps/CyberChef/node_modules.
 */

const path = require("path");

const cyberchef = path.resolve(__dirname, "../deps/CyberChef");
const nodeModules = path.join(cyberchef, "node_modules");
const fromCyberChef = (name) => require.resolve(name, {paths: [cyberchef]});
const webpack = require(fromCyberChef("webpack"));

const config = {
    mode: "production",
    target: ["web", "es2022"],
    entry: path.join(__dirname, "bridge.mjs"),
    output: {
        path: path.resolve(__dirname, "../ida_cyberchef/data"),
        filename: "CyberChef.js",
        // Recipe loads its operation modules with an eager dynamic import, so
        // everything stays in this one file.
        chunkLoading: false,
    },
    resolve: {
        extensions: [".mjs", ".js", ".json"],
        modules: ["node_modules", nodeModules],
        fallback: {
            "assert": fromCyberChef("assert/"),
            "buffer": fromCyberChef("buffer/"),
            "crypto": fromCyberChef("crypto-browserify"),
            "events": fromCyberChef("events/"),
            "path": fromCyberChef("path/"),
            "stream": fromCyberChef("stream-browserify"),
            "url": fromCyberChef("url/"),
            "util": fromCyberChef("util/"),
            "zlib": fromCyberChef("browserify-zlib"),
            "child_process": false,
            "fs": false,
            "net": false,
            "tls": false,
            "vm": false,
        },
    },
    resolveLoader: {
        modules: [nodeModules],
    },
    module: {
        // argon2-browser loads argon2.wasm by itself.
        noParse: /argon2\.wasm$/,
        rules: [
            {
                // CyberChef's sources default-import packages that only have
                // named exports (es6-promisify, flat, d3) and rely on Babel's
                // CommonJS interop for that. Only module syntax and block
                // scoping are converted; V8 runs everything else as written.
                test: /\.m?js$/,
                exclude: /node_modules\/(?!crypto-api)/,
                type: "javascript/auto",
                resolve: {fullySpecified: false},
                loader: "babel-loader",
                options: {
                    babelrc: false,
                    configFile: false,
                    cacheDirectory: true,
                    plugins: [
                        fromCyberChef("@babel/plugin-syntax-import-attributes"),
                        fromCyberChef("@babel/plugin-transform-modules-commonjs"),
                        // Upstream ships let/const as var, and some code (FuzzyMatch)
                        // only works without the temporal dead zone.
                        fromCyberChef("@babel/plugin-transform-block-scoping"),
                    ],
                    generatorOpts: {importAttributesKeyword: "with"},
                },
            },
            {
                test: /\.m?js$/,
                type: "javascript/auto",
                resolve: {fullySpecified: false},
            },
            {
                test: /node-forge/,
                loader: "imports-loader",
                options: {additionalCode: "var jQuery = false;"},
            },
            {
                test: /argon2\.wasm$/,
                loader: "base64-loader",
                type: "javascript/auto",
            },
            {
                test: /prime.worker.min.js$/,
                type: "asset/source",
            },
            {
                test: /\.(png|jpg|gif|svg|ttf|woff2?)$/,
                type: "asset/inline",
            },
            {
                test: /\.fnt$/,
                type: "asset/inline",
                generator: {dataUrl: {mimetype: "text/plain"}},
            },
        ],
    },
    plugins: [
        new webpack.ProvidePlugin({
            process: "process/browser",
            Buffer: ["buffer", "Buffer"],
        }),
        // CyberChef and its libraries run as in the web app's worker: in
        // their browser mode, on the Web APIs from polyfills.mjs.
        new webpack.DefinePlugin({"process.browser": "true"}),
        new webpack.BannerPlugin({
            banner: [
                "/*",
                " * CyberChef - The Cyber Swiss Army Knife",
                " * Copyright Crown Copyright 2016-2026, licensed under the Apache License, Version 2.0.",
                " * Built by ida-cyberchef from js/bridge.mjs; do not edit.",
                " */",
            ].join("\n"),
            raw: true,
        }),
    ],
    optimization: {
        minimize: false,
        nodeEnv: false,
    },
    performance: {hints: false},
    stats: "errors-warnings",
    ignoreWarnings: [/source-map/, /dependency is an expression/, /Can't resolve 'sodium'/],
};

webpack(config, (error, stats) => {
    if (error) {
        console.error(error);
        process.exit(1);
    }
    console.log(stats.toString(config.stats));
    process.exit(stats.hasErrors() ? 1 : 0);
});
