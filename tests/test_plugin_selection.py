import importlib
import sys
import types
from enum import IntEnum

import pytest


@pytest.fixture
def plugin_module(monkeypatch):
    plugin_name = "ida_cyberchef.plugin"
    sys.modules.pop(plugin_name, None)

    state = {
        "viewer": object(),
        "selection": (True, 0x401000, 0x401010),
        "buffer": b"\x01\x02\x03\x04",
        "get_bytes_calls": [],
    }

    ida_bytes = types.ModuleType("ida_bytes")

    def get_bytes(start, length):
        assert start != ida_idaapi.BADADDR
        assert length > 0
        state["get_bytes_calls"].append((start, length))
        return state["buffer"]

    ida_bytes.get_bytes = get_bytes
    ida_bytes.patch_bytes = lambda *args, **kwargs: None
    ida_bytes.set_cmt = lambda *args, **kwargs: None

    ida_idaapi = types.ModuleType("ida_idaapi")

    class plugmod_t:
        pass

    class plugin_t:
        pass

    ida_idaapi.plugmod_t = plugmod_t
    ida_idaapi.plugin_t = plugin_t
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
    ida_idaapi.PLUGIN_MULTI = 0
    ida_idaapi.ea_t = int

    ida_kernwin = types.ModuleType("ida_kernwin")

    class UI_Hooks:
        def __init__(self, *args, **kwargs):
            pass

        def hook(self):
            pass

        def unhook(self):
            pass

    class action_handler_t:
        def __init__(self, *args, **kwargs):
            pass

    class PluginForm:
        def __init__(self, *args, **kwargs):
            pass

    class action_desc_t:
        def __init__(self, *args, **kwargs):
            pass

    ida_kernwin.UI_Hooks = UI_Hooks
    ida_kernwin.action_handler_t = action_handler_t
    ida_kernwin.PluginForm = PluginForm
    ida_kernwin.action_desc_t = action_desc_t
    ida_kernwin.BWN_HEXVIEW = 1
    ida_kernwin.BWN_DISASM = 2
    ida_kernwin.AST_ENABLE = 1
    ida_kernwin.AST_DISABLE = 0
    ida_kernwin.AST_ENABLE_ALWAYS = 2
    ida_kernwin.SETMENU_APP = 0
    ida_kernwin.get_current_viewer = lambda: state["viewer"]
    ida_kernwin.get_widget_type = lambda viewer: state["widget_type"]
    ida_kernwin.read_range_selection = lambda viewer: state["selection"]
    ida_kernwin.get_screen_ea = lambda: 0
    ida_kernwin.find_widget = lambda caption: None
    ida_kernwin.activate_widget = lambda *args, **kwargs: None
    ida_kernwin.register_action = lambda *args, **kwargs: None
    ida_kernwin.unregister_action = lambda *args, **kwargs: None
    ida_kernwin.attach_action_to_menu = lambda *args, **kwargs: None
    ida_kernwin.detach_action_from_menu = lambda *args, **kwargs: None
    ida_kernwin.attach_action_to_popup = lambda *args, **kwargs: None
    ida_kernwin.warning = lambda *args, **kwargs: None

    pyside6 = types.ModuleType("PySide6")
    pyside6.QtWidgets = types.SimpleNamespace(QVBoxLayout=type("QVBoxLayout", (), {}))

    cyberchef_widget = types.ModuleType("ida_cyberchef.cyberchef_widget")
    cyberchef_widget.CyberChefWidget = type("CyberChefWidget", (), {})

    input_model = types.ModuleType("ida_cyberchef.qt_models.input_model")

    class InputSource(IntEnum):
        MANUAL = 0
        FROM_CURSOR = 1
        FROM_SELECTION = 2
        FROM_LOCATION = 3

    input_model.InputSource = InputSource

    monkeypatch.setitem(sys.modules, "ida_bytes", ida_bytes)
    monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)
    monkeypatch.setitem(sys.modules, "PySide6", pyside6)
    monkeypatch.setitem(sys.modules, "ida_cyberchef.cyberchef_widget", cyberchef_widget)
    monkeypatch.setitem(sys.modules, "ida_cyberchef.qt_models.input_model", input_model)

    module = importlib.import_module(plugin_name)
    yield module, state
    sys.modules.pop(plugin_name, None)


@pytest.mark.parametrize("widget_type_name", ["BWN_HEXVIEW", "BWN_DISASM"])
def test_read_and_validate_selection_accepts_hex_and_disasm_views(
    plugin_module, widget_type_name
):
    plugin, state = plugin_module
    state["widget_type"] = getattr(plugin.ida_kernwin, widget_type_name)

    ok, start, end, length = plugin._read_and_validate_selection(state["viewer"])

    assert ok is True
    assert (start, end, length) == (0x401000, 0x401010, 0x10)


@pytest.mark.parametrize("widget_type_name", ["BWN_HEXVIEW", "BWN_DISASM"])
def test_populate_from_selection_reads_hex_and_disasm_views(
    plugin_module, widget_type_name
):
    plugin, state = plugin_module
    state["widget_type"] = getattr(plugin.ida_kernwin, widget_type_name)

    class FakeInputModel:
        def __init__(self):
            self.calls = []

        def set_external_data(self, data, address=None):
            self.calls.append((data, address))

    class FakeWidget:
        def __init__(self):
            self._input_model = FakeInputModel()

        def get_input_model(self):
            return self._input_model

    hook = object.__new__(plugin.UILocationHook)
    hook.w = FakeWidget()

    hook.populate_from_selection()

    assert state["get_bytes_calls"] == [(0x401000, 0x10)]
    assert hook.w.get_input_model().calls == [(state["buffer"], 0x401000)]
