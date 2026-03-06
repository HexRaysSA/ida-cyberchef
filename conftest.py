import os
from pathlib import Path

QT_TEST_ENV_VAR = "IDA_CYBERCHEF_ENABLE_QT_TESTS"
TRUTHY_VALUES = {"1", "true", "yes", "on"}


QT_TEST_NAMES = {
    "test_ui_verification.py",
}


def _qt_tests_enabled() -> bool:
    return os.environ.get(QT_TEST_ENV_VAR, "").strip().lower() in TRUTHY_VALUES


def pytest_ignore_collect(collection_path: Path, config) -> bool:
    if _qt_tests_enabled():
        return False

    if collection_path.parent.name != "tests":
        return False

    name = collection_path.name
    return (
        name.startswith("test_qt_")
        or name.endswith("_panel.py")
        or name.endswith("_widget.py")
        or name in QT_TEST_NAMES
    )
