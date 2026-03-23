import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest

PLUGIN_PATH = (
    Path(__file__).resolve().parents[1] / "ida_cyberchef" / "plugin" / "__init__.py"
)


def _load_plugin_module(monkeypatch: pytest.MonkeyPatch):
    ida_bytes = types.ModuleType("ida_bytes")
    patched_memory: dict[int, bytes] = {}
    ida_bytes.patch_calls: list[tuple[int, bytes]] = []

    def patch_bytes(address: int, data: bytes) -> None:
        ida_bytes.patch_calls.append((address, data))
        patched_memory[address] = data

    ida_bytes.patch_bytes = patch_bytes
    ida_bytes.get_bytes = lambda address, size: patched_memory.get(address, b"\x00" * size)
    ida_bytes.set_cmt = lambda ea, text, repeatable: None

    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    ida_idaapi.PLUGIN_MULTI = 1
    ida_idaapi.ea_t = int
    ida_idaapi.plugmod_t = type("plugmod_t", (), {})
    ida_idaapi.plugin_t = type("plugin_t", (), {})

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.warning_calls: list[str] = []
    ida_kernwin.UI_Hooks = type("UI_Hooks", (), {})
    ida_kernwin.action_handler_t = type("action_handler_t", (), {})
    ida_kernwin.PluginForm = type("PluginForm", (), {})
    ida_kernwin.warning = ida_kernwin.warning_calls.append

    pyside6 = types.ModuleType("PySide6")
    qtwidgets = types.ModuleType("PySide6.QtWidgets")
    qtwidgets.QVBoxLayout = type(
        "QVBoxLayout",
        (),
        {
            "setContentsMargins": lambda self, *args: None,
            "setSpacing": lambda self, *args: None,
            "addWidget": lambda self, *args: None,
        },
    )
    pyside6.QtWidgets = qtwidgets

    ida_pkg = types.ModuleType("ida_cyberchef")
    ida_pkg.__path__ = [str(PLUGIN_PATH.parents[1])]
    cyberchef_widget = types.ModuleType("ida_cyberchef.cyberchef_widget")
    cyberchef_widget.CyberChefWidget = type("CyberChefWidget", (), {})
    qt_models_pkg = types.ModuleType("ida_cyberchef.qt_models")
    qt_models_pkg.__path__ = [str(PLUGIN_PATH.parents[1] / "qt_models")]
    input_model = types.ModuleType("ida_cyberchef.qt_models.input_model")
    input_model.InputSource = type(
        "InputSource",
        (),
        {
            "MANUAL": "MANUAL",
            "FROM_CURSOR": "FROM_CURSOR",
            "FROM_SELECTION": "FROM_SELECTION",
            "FROM_LOCATION": "FROM_LOCATION",
        },
    )

    for name, module in {
        "ida_bytes": ida_bytes,
        "ida_idaapi": ida_idaapi,
        "ida_kernwin": ida_kernwin,
        "PySide6": pyside6,
        "PySide6.QtWidgets": qtwidgets,
        "ida_cyberchef": ida_pkg,
        "ida_cyberchef.cyberchef_widget": cyberchef_widget,
        "ida_cyberchef.qt_models": qt_models_pkg,
        "ida_cyberchef.qt_models.input_model": input_model,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    spec = importlib.util.spec_from_file_location("ida_cyberchef.plugin", PLUGIN_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "ida_cyberchef.plugin", module)
    spec.loader.exec_module(module)
    return module, ida_bytes, ida_idaapi, ida_kernwin


@pytest.mark.parametrize(
    ("address", "data", "expected_message"),
    [
        pytest.param(0xFFFFFFFFFFFFFFFF, b"\xAA", "Cannot patch IDB: invalid address", id="badaddr"),
        pytest.param("0x401000", b"\xAA", "Cannot patch IDB: invalid address", id="non-int-address"),
        pytest.param(0x401000, b"", "Cannot patch IDB: invalid data", id="empty-bytes"),
        pytest.param(0x401000, "AA", "Cannot patch IDB: invalid data", id="non-bytes-data"),
    ],
)
def test_on_copy_to_db_invalid_inputs_warn_and_return(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    address,
    data,
    expected_message: str,
):
    plugin, ida_bytes, _ida_idaapi, ida_kernwin = _load_plugin_module(monkeypatch)
    form = plugin.CyberChefForm()

    with caplog.at_level(logging.WARNING):
        form._on_copy_to_db(address, data)

    assert ida_bytes.patch_calls == []
    assert any(expected_message in message for message in ida_kernwin.warning_calls)
    assert expected_message in caplog.text


def test_on_copy_to_db_valid_inputs_patch_bytes(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    plugin, ida_bytes, _ida_idaapi, ida_kernwin = _load_plugin_module(monkeypatch)
    form = plugin.CyberChefForm()

    with caplog.at_level(logging.INFO):
        form._on_copy_to_db(0x401000, b"\xDE\xAD")

    assert ida_bytes.patch_calls == [(0x401000, b"\xDE\xAD")]
    assert ida_kernwin.warning_calls == []
    assert "Patched 2 bytes at 0x401000" in caplog.text
