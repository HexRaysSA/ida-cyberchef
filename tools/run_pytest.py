from __future__ import annotations

import os
import subprocess
import sys

QT_TEST_ENV_VAR = "IDA_CYBERCHEF_ENABLE_QT_TESTS"
TRUTHY_VALUES = {"1", "true", "yes", "on"}


def _enabled(env_var: str) -> bool:
    return os.environ.get(env_var, "").strip().lower() in TRUTHY_VALUES


def main() -> int:
    cmd = [sys.executable, "-m", "pytest"]

    if _enabled(QT_TEST_ENV_VAR):
        cmd.extend(["--override-ini", "addopts="])
        if _enabled("PYTEST_DISABLE_PLUGIN_AUTOLOAD"):
            cmd.extend(["-p", "pytestqt.plugin"])

    cmd.extend(sys.argv[1:])
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
