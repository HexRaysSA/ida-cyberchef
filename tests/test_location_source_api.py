import importlib.util
import sys
import types
from enum import IntEnum
from pathlib import Path


REPO_ROOT = Path("/home/runner/work/ida-cyberchef/ida-cyberchef")


class _FakeInputSource(IntEnum):
    MANUAL = 0
    FROM_CURSOR = 1
    FROM_SELECTION = 2
    FROM_LOCATION = 3


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name, REPO_ROOT / relative_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _install_input_panel_stubs():
    py_side6 = types.ModuleType("PySide6")
    qt_core = types.ModuleType("PySide6.QtCore")
    qt_core.Qt = types.SimpleNamespace(ScrollBarAsNeeded=0)
    qt_gui = types.ModuleType("PySide6.QtGui")
    qt_gui.QResizeEvent = type("QResizeEvent", (), {})
    qt_widgets = types.ModuleType("PySide6.QtWidgets")

    widget_names = [
        "QButtonGroup",
        "QComboBox",
        "QHBoxLayout",
        "QLabel",
        "QRadioButton",
        "QTextEdit",
        "QVBoxLayout",
        "QWidget",
    ]
    for name in widget_names:
        setattr(qt_widgets, name, type(name, (), {}))

    py_side6.QtCore = qt_core
    py_side6.QtGui = qt_gui
    py_side6.QtWidgets = qt_widgets

    sys.modules["PySide6"] = py_side6
    sys.modules["PySide6.QtCore"] = qt_core
    sys.modules["PySide6.QtGui"] = qt_gui
    sys.modules["PySide6.QtWidgets"] = qt_widgets

    sys.modules["ida_cyberchef"] = types.ModuleType("ida_cyberchef")
    sys.modules["ida_cyberchef.core"] = types.ModuleType("ida_cyberchef.core")
    sys.modules["ida_cyberchef.widgets"] = types.ModuleType("ida_cyberchef.widgets")
    sys.modules["ida_cyberchef.qt_models"] = types.ModuleType(
        "ida_cyberchef.qt_models"
    )

    hex_formatter = types.ModuleType("ida_cyberchef.core.hex_formatter")
    hex_formatter.HexFormatter = type("HexFormatter", (), {})
    sys.modules["ida_cyberchef.core.hex_formatter"] = hex_formatter

    input_parser = types.ModuleType("ida_cyberchef.core.input_parser")
    input_parser.InputFormat = type("InputFormat", (), {})
    sys.modules["ida_cyberchef.core.input_parser"] = input_parser

    input_model = types.ModuleType("ida_cyberchef.qt_models.input_model")
    input_model.InputModel = type("InputModel", (), {})
    input_model.InputSource = _FakeInputSource
    sys.modules["ida_cyberchef.qt_models.input_model"] = input_model

    location_input_widget = types.ModuleType(
        "ida_cyberchef.widgets.location_input_widget"
    )
    location_input_widget.LocationInputWidget = type("LocationInputWidget", (), {})
    sys.modules["ida_cyberchef.widgets.location_input_widget"] = location_input_widget


def _install_cyberchef_widget_stubs():
    py_side6 = types.ModuleType("PySide6")
    qt_widgets = types.ModuleType("PySide6.QtWidgets")
    qt_widgets.QSizePolicy = type("QSizePolicy", (), {})
    qt_widgets.QVBoxLayout = type("QVBoxLayout", (), {})
    qt_widgets.QWidget = type("QWidget", (), {})

    py_side6.QtWidgets = qt_widgets

    sys.modules["PySide6"] = py_side6
    sys.modules["PySide6.QtWidgets"] = qt_widgets

    sys.modules["ida_cyberchef"] = types.ModuleType("ida_cyberchef")
    sys.modules["ida_cyberchef.core"] = types.ModuleType("ida_cyberchef.core")
    sys.modules["ida_cyberchef.qt_models"] = types.ModuleType(
        "ida_cyberchef.qt_models"
    )
    sys.modules["ida_cyberchef.widgets"] = types.ModuleType("ida_cyberchef.widgets")

    operation_registry = types.ModuleType("ida_cyberchef.core.operation_registry")
    operation_registry.OperationRegistry = type("OperationRegistry", (), {})
    sys.modules["ida_cyberchef.core.operation_registry"] = operation_registry

    execution_model = types.ModuleType("ida_cyberchef.qt_models.execution_model")
    execution_model.ExecutionModel = type("ExecutionModel", (), {})
    sys.modules["ida_cyberchef.qt_models.execution_model"] = execution_model

    input_model = types.ModuleType("ida_cyberchef.qt_models.input_model")
    input_model.InputModel = type("InputModel", (), {})
    sys.modules["ida_cyberchef.qt_models.input_model"] = input_model

    recipe_model = types.ModuleType("ida_cyberchef.qt_models.recipe_model")
    recipe_model.RecipeModel = type("RecipeModel", (), {})
    sys.modules["ida_cyberchef.qt_models.recipe_model"] = recipe_model

    input_panel = types.ModuleType("ida_cyberchef.widgets.input_panel")
    input_panel.InputPanel = type("InputPanel", (), {})
    sys.modules["ida_cyberchef.widgets.input_panel"] = input_panel

    operation_browser = types.ModuleType(
        "ida_cyberchef.widgets.operation_browser_widget"
    )
    operation_browser.OperationBrowserWidget = type("OperationBrowserWidget", (), {})
    sys.modules["ida_cyberchef.widgets.operation_browser_widget"] = operation_browser

    output_panel = types.ModuleType("ida_cyberchef.widgets.output_panel")
    output_panel.OutputPanel = type("OutputPanel", (), {})
    sys.modules["ida_cyberchef.widgets.output_panel"] = output_panel

    recipe_panel = types.ModuleType("ida_cyberchef.widgets.recipe_panel")
    recipe_panel.RecipePanel = type("RecipePanel", (), {})
    sys.modules["ida_cyberchef.widgets.recipe_panel"] = recipe_panel


def _install_plugin_stubs():
    ida_bytes = types.ModuleType("ida_bytes")
    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = -1
    ida_idaapi.ea_t = int
    ida_idaapi.plugmod_t = type("plugmod_t", (), {})
    ida_idaapi.plugin_t = type("plugin_t", (), {})
    ida_idaapi.PLUGIN_MULTI = 0

    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.UI_Hooks = type("UI_Hooks", (), {})
    ida_kernwin.PluginForm = type("PluginForm", (), {})
    ida_kernwin.action_handler_t = type("action_handler_t", (), {})
    ida_kernwin.action_desc_t = type("action_desc_t", (), {})
    ida_kernwin.BWN_HEXVIEW = 1
    ida_kernwin.BWN_DISASM = 2
    ida_kernwin.TCCPT_IDAPLACE = 3
    ida_kernwin.AST_ENABLE_ALWAYS = 1
    ida_kernwin.AST_ENABLE = 1
    ida_kernwin.AST_DISABLE = 0
    ida_kernwin.SETMENU_APP = 0

    qt_widgets = types.ModuleType("PySide6.QtWidgets")
    qt_widgets.QVBoxLayout = type("QVBoxLayout", (), {})
    py_side6 = types.ModuleType("PySide6")
    py_side6.QtWidgets = qt_widgets

    sys.modules["ida_bytes"] = ida_bytes
    sys.modules["ida_idaapi"] = ida_idaapi
    sys.modules["ida_kernwin"] = ida_kernwin
    sys.modules["PySide6"] = py_side6
    sys.modules["PySide6.QtWidgets"] = qt_widgets

    sys.modules["ida_cyberchef"] = types.ModuleType("ida_cyberchef")

    cyberchef_widget = types.ModuleType("ida_cyberchef.cyberchef_widget")
    cyberchef_widget.CyberChefWidget = type("CyberChefWidget", (), {})
    sys.modules["ida_cyberchef.cyberchef_widget"] = cyberchef_widget

    input_model = types.ModuleType("ida_cyberchef.qt_models.input_model")
    input_model.InputSource = _FakeInputSource
    sys.modules["ida_cyberchef.qt_models"] = types.ModuleType(
        "ida_cyberchef.qt_models"
    )
    sys.modules["ida_cyberchef.qt_models.input_model"] = input_model


def test_input_panel_set_location_source_updates_model_and_widgets(monkeypatch):
    _install_input_panel_stubs()
    module = _load_module(
        "testable_input_panel", "ida_cyberchef/widgets/input_panel.py"
    )

    panel = module.InputPanel.__new__(module.InputPanel)

    events = []

    class FakeInputModel:
        def set_input_source(self, source):
            events.append(("source", source))

        def set_location_params(self, address, length):
            events.append(("params", address, length))

    class FakeRadio:
        def setChecked(self, checked):
            events.append(("checked", checked))

    class FakeLocationWidget:
        def set_location(self, address, length):
            events.append(("widget", address, length))

    def fake_on_source_changed():
        events.append(("changed",))

    panel._input_model = FakeInputModel()
    panel._location_radio = FakeRadio()
    panel._location_widget = FakeLocationWidget()
    panel._on_source_changed = fake_on_source_changed

    panel.set_location_source(0x401000, 0x20)

    assert events == [
        ("source", _FakeInputSource.FROM_LOCATION),
        ("checked", True),
        ("changed",),
        ("params", 0x401000, 0x20),
        ("widget", 0x401000, 0x20),
    ]


def test_cyberchef_widget_set_location_source_delegates_to_input_panel():
    _install_cyberchef_widget_stubs()
    module = _load_module(
        "testable_cyberchef_widget", "ida_cyberchef/cyberchef_widget.py"
    )

    widget = module.CyberChefWidget.__new__(module.CyberChefWidget)

    calls = []

    class FakeInputPanel:
        def set_location_source(self, address, length):
            calls.append((address, length))

    widget._input_panel = FakeInputPanel()

    widget.set_location_source(0x500000, 0x40)

    assert calls == [(0x500000, 0x40)]


def test_plugin_population_uses_public_widget_api():
    _install_plugin_stubs()
    module = _load_module("testable_plugin", "ida_cyberchef/plugin/__init__.py")

    calls = []

    class FakeWidget:
        def set_location_source(self, address, length):
            calls.append((address, length))

    form = types.SimpleNamespace(w=FakeWidget())

    module._populate_widget_from_selection(form, 0x600000, 0x80)

    assert calls == [(0x600000, 0x80)]
