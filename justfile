cyberchef := "deps/CyberChef"

# Install CyberChef's npm dependencies (build time only; the plugin needs no npm).
install-npm:
    cd {{ cyberchef }} && npm ci --no-audit --no-fund

# Generate CyberChef's OperationConfig.json and operation module index.
config: install-npm
    cd {{ cyberchef }} && echo '[]' > src/core/config/OperationConfig.json
    cd {{ cyberchef }} && node --no-warnings src/core/config/scripts/generateOpsIndex.mjs
    cd {{ cyberchef }} && node --no-warnings src/core/config/scripts/generateConfig.mjs

# Build ida_cyberchef/data/CyberChef.js and regenerate the operation schema and docs.
build: config
    node js/build.cjs
    python tools/generate_operation_schema.py
    python tools/generate_docs.py

clean:
    rm -rf {{ cyberchef }}/node_modules ida_cyberchef/data/CyberChef.js

test:
    pytest tests/

lint:
    -ruff format .
    ruff check .
    ruff check --select I .
    mypy --check-untyped-defs --ignore-missing-imports --exclude tools .
