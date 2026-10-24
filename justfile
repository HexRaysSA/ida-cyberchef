cyberchef := "deps/CyberChef"

# Install CyberChef's npm dependencies (build time only; the plugin needs no npm).
install-npm:
    cd {{ cyberchef }} && npm ci --no-audit --no-fund

# Generate CyberChef's OperationConfig.json, operation module index and other
# generated sources, with CyberChef's own build step.
config: install-npm
    cd {{ cyberchef }} && npx grunt exec:generateConfig

# Build ida_cyberchef/data/CyberChef.js and regenerate the operation schema,
# docs and CyberChef's test vectors.
build: config
    node js/build.cjs
    python tools/generate_operation_schema.py
    python tools/generate_docs.py
    node --no-warnings --no-deprecation tools/extract_upstream_vectors.mjs

clean:
    rm -rf {{ cyberchef }}/node_modules ida_cyberchef/data/CyberChef.js

test:
    pytest tests/

lint:
    -ruff format .
    ruff check .
    ruff check --select I .
    mypy --check-untyped-defs --ignore-missing-imports --exclude tools .
