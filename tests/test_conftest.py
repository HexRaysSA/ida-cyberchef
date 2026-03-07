from contextlib import contextmanager
import os
from pathlib import Path

import conftest


@contextmanager
def restored_qt_env():
    original_qt = os.environ.get(conftest.QT_TEST_ENV_VAR)
    original_gui = os.environ.get(conftest.GUI_TEST_ENV_VAR)

    try:
        yield
    finally:
        if original_qt is None:
            os.environ.pop(conftest.QT_TEST_ENV_VAR, None)
        else:
            os.environ[conftest.QT_TEST_ENV_VAR] = original_qt

        if original_gui is None:
            os.environ.pop(conftest.GUI_TEST_ENV_VAR, None)
        else:
            os.environ[conftest.GUI_TEST_ENV_VAR] = original_gui


def test_qt_model_tests_require_qt_env():
    with restored_qt_env():
        os.environ.pop(conftest.QT_TEST_ENV_VAR, None)
        os.environ.pop(conftest.GUI_TEST_ENV_VAR, None)

        assert (
            conftest.pytest_ignore_collect(
                Path("tests/test_qt_input_model.py"), config=None
            )
            is True
        )


def test_qt_model_tests_run_when_qt_env_enabled():
    with restored_qt_env():
        os.environ[conftest.QT_TEST_ENV_VAR] = "1"
        os.environ.pop(conftest.GUI_TEST_ENV_VAR, None)

        assert (
            conftest.pytest_ignore_collect(
                Path("tests/test_qt_input_model.py"), config=None
            )
            is False
        )


def test_gui_tests_require_gui_env_even_when_qt_env_enabled():
    with restored_qt_env():
        os.environ[conftest.QT_TEST_ENV_VAR] = "1"
        os.environ.pop(conftest.GUI_TEST_ENV_VAR, None)

        assert (
            conftest.pytest_ignore_collect(Path("tests/test_input_panel.py"), config=None)
            is True
        )


def test_gui_tests_run_when_qt_and_gui_env_enabled():
    with restored_qt_env():
        os.environ[conftest.QT_TEST_ENV_VAR] = "1"
        os.environ[conftest.GUI_TEST_ENV_VAR] = "1"

        assert (
            conftest.pytest_ignore_collect(Path("tests/test_input_panel.py"), config=None)
            is False
        )
