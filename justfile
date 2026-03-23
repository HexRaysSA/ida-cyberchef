install-npm:
    cd deps/CyberChef && npm install


build: install-npm
    cd deps/CyberChef && npm run node
    cp deps/CyberChef/build/node/CyberChef.js ida_cyberchef/data/CyberChef.js


clean:
    rm -rf deps/CyberChef/build ida_cyberchef/data/CyberChef.js

test:
    pytest tests/
