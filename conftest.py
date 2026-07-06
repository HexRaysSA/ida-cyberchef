import os
from pathlib import Path

QT_TEST_ENV_VAR = "IDA_CYBERCHEF_ENABLE_QT_TESTS"
GUI_TEST_ENV_VAR = "IDA_CYBERCHEF_ENABLE_GUI_TESTS"
TRUTHY_VALUES = {"1", "true", "yes", "on"}


GUI_TEST_NAMES = {
    "test_ui_verification.py",
}


def _tests_enabled(env_var: str) -> bool:
    return os.environ.get(env_var, "").strip().lower() in TRUTHY_VALUES


def pytest_ignore_collect(collection_path: Path, config) -> bool:
    if collection_path.parent.name != "tests":
        return False

    name = collection_path.name
    is_qt_model_test = name.startswith("test_qt_")
    is_gui_test = name.endswith(("_panel.py", "_widget.py")) or name in GUI_TEST_NAMES

    if is_qt_model_test:
        return not _tests_enabled(QT_TEST_ENV_VAR)

    if is_gui_test:
        return not (_tests_enabled(QT_TEST_ENV_VAR) and _tests_enabled(GUI_TEST_ENV_VAR))

    return False
