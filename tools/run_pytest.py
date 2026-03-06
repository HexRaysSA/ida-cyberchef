from __future__ import annotations

import os
import subprocess
import sys

QT_TEST_ENV_VAR = "IDA_CYBERCHEF_ENABLE_QT_TESTS"
TRUTHY_VALUES = {"1", "true", "yes", "on"}


def main() -> int:
    cmd = [sys.executable, "-m", "pytest"]

    if os.environ.get(QT_TEST_ENV_VAR, "").strip().lower() in TRUTHY_VALUES:
        cmd.extend(["--override-ini", "addopts=", "-p", "pytestqt.plugin"])

    cmd.extend(sys.argv[1:])
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
