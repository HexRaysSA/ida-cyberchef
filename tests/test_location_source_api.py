import importlib.util
import sys
import types
from enum import IntEnum
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


class _FakeInputSource(IntEnum):
    MANUAL = 0
    FROM_CURSOR = 1
    FROM_SELECTION = 2
    FROM_LOCATION = 3


def _fake_type(name: str):
    return type(name, (), {})


def _stub_module(monkeypatch, name: str, **attrs):
    module = types.ModuleType(name)
    for attr_name, value in attrs.items():
        setattr(module, attr_name, value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _load_module(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(
        module_name, REPO_ROOT / relative_path
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _stub_input_panel_imports(monkeypatch):
    qt_core = _stub_module(
        monkeypatch, "PySide6.QtCore", Qt=types.SimpleNamespace(ScrollBarAsNeeded=0)
    )
    qt_gui = _stub_module(monkeypatch, "PySide6.QtGui", QResizeEvent=_fake_type("QResizeEvent"))
    qt_widgets = _stub_module(
        monkeypatch,
        "PySide6.QtWidgets",
        QButtonGroup=_fake_type("QButtonGroup"),
        QComboBox=_fake_type("QComboBox"),
        QHBoxLayout=_fake_type("QHBoxLayout"),
        QLabel=_fake_type("QLabel"),
        QRadioButton=_fake_type("QRadioButton"),
        QTextEdit=_fake_type("QTextEdit"),
        QVBoxLayout=_fake_type("QVBoxLayout"),
        QWidget=_fake_type("QWidget"),
    )
    _stub_module(
        monkeypatch, "PySide6", QtCore=qt_core, QtGui=qt_gui, QtWidgets=qt_widgets
    )
    _stub_module(monkeypatch, "ida_cyberchef")
    _stub_module(monkeypatch, "ida_cyberchef.core")
    _stub_module(monkeypatch, "ida_cyberchef.qt_models")
    _stub_module(monkeypatch, "ida_cyberchef.widgets")
    _stub_module(
        monkeypatch,
        "ida_cyberchef.core.hex_formatter",
        HexFormatter=_fake_type("HexFormatter"),
    )
    _stub_module(
        monkeypatch, "ida_cyberchef.core.input_parser", InputFormat=_fake_type("InputFormat")
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.qt_models.input_model",
        InputModel=_fake_type("InputModel"),
        InputSource=_FakeInputSource,
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.widgets.location_input_widget",
        LocationInputWidget=_fake_type("LocationInputWidget"),
    )


def _stub_cyberchef_widget_imports(monkeypatch):
    qt_widgets = _stub_module(
        monkeypatch,
        "PySide6.QtWidgets",
        QSizePolicy=_fake_type("QSizePolicy"),
        QVBoxLayout=_fake_type("QVBoxLayout"),
        QWidget=_fake_type("QWidget"),
    )
    _stub_module(monkeypatch, "PySide6", QtWidgets=qt_widgets)
    _stub_module(monkeypatch, "ida_cyberchef")
    _stub_module(monkeypatch, "ida_cyberchef.core")
    _stub_module(monkeypatch, "ida_cyberchef.qt_models")
    _stub_module(monkeypatch, "ida_cyberchef.widgets")
    _stub_module(
        monkeypatch,
        "ida_cyberchef.core.operation_registry",
        OperationRegistry=_fake_type("OperationRegistry"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.qt_models.execution_model",
        ExecutionModel=_fake_type("ExecutionModel"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.qt_models.input_model",
        InputModel=_fake_type("InputModel"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.qt_models.recipe_model",
        RecipeModel=_fake_type("RecipeModel"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.widgets.input_panel",
        InputPanel=_fake_type("InputPanel"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.widgets.operation_browser_widget",
        OperationBrowserWidget=_fake_type("OperationBrowserWidget"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.widgets.output_panel",
        OutputPanel=_fake_type("OutputPanel"),
    )
    _stub_module(
        monkeypatch,
        "ida_cyberchef.widgets.recipe_panel",
        RecipePanel=_fake_type("RecipePanel"),
    )


def _stub_plugin_imports(monkeypatch):
    qt_widgets = _stub_module(
        monkeypatch, "PySide6.QtWidgets", QVBoxLayout=_fake_type("QVBoxLayout")
    )
    _stub_module(monkeypatch, "PySide6", QtWidgets=qt_widgets)
    _stub_module(monkeypatch, "ida_bytes")
    _stub_module(
        monkeypatch,
        "ida_idaapi",
        BADADDR=-1,
        PLUGIN_MULTI=0,
        ea_t=int,
        plugmod_t=_fake_type("plugmod_t"),
        plugin_t=_fake_type("plugin_t"),
    )
    _stub_module(
        monkeypatch,
        "ida_kernwin",
        UI_Hooks=_fake_type("UI_Hooks"),
        PluginForm=_fake_type("PluginForm"),
        action_handler_t=_fake_type("action_handler_t"),
        action_desc_t=_fake_type("action_desc_t"),
        BWN_HEXVIEW=1,
        BWN_DISASM=2,
        TCCPT_IDAPLACE=3,
        AST_ENABLE_ALWAYS=1,
        AST_ENABLE=1,
        AST_DISABLE=0,
        SETMENU_APP=0,
    )
    _stub_module(monkeypatch, "ida_cyberchef")
    _stub_module(
        monkeypatch,
        "ida_cyberchef.cyberchef_widget",
        CyberChefWidget=_fake_type("CyberChefWidget"),
    )
    _stub_module(monkeypatch, "ida_cyberchef.qt_models")
    _stub_module(
        monkeypatch,
        "ida_cyberchef.qt_models.input_model",
        InputSource=_FakeInputSource,
    )


def test_input_panel_set_location_source_updates_model_and_widgets(monkeypatch):
    _stub_input_panel_imports(monkeypatch)
    module = _load_module(
        "testable_input_panel", "ida_cyberchef/widgets/input_panel.py"
    )
    panel = module.InputPanel.__new__(module.InputPanel)
    events = []

    panel._input_model = types.SimpleNamespace(
        set_input_source=lambda source: events.append(("source", source)),
        set_location_params=lambda address, length: events.append(
            ("params", address, length)
        ),
    )
    panel._location_radio = types.SimpleNamespace(
        setChecked=lambda checked: events.append(("checked", checked))
    )
    panel._location_widget = types.SimpleNamespace(
        set_location=lambda address, length: events.append(("widget", address, length))
    )
    panel._on_source_changed = lambda: events.append(("changed",))

    panel.set_location_source(0x401000, 0x20)

    assert events == [
        ("source", _FakeInputSource.FROM_LOCATION),
        ("checked", True),
        ("changed",),
        ("params", 0x401000, 0x20),
        ("widget", 0x401000, 0x20),
    ]


def test_cyberchef_widget_set_location_source_delegates_to_input_panel(monkeypatch):
    _stub_cyberchef_widget_imports(monkeypatch)
    module = _load_module(
        "testable_cyberchef_widget", "ida_cyberchef/cyberchef_widget.py"
    )
    widget = module.CyberChefWidget.__new__(module.CyberChefWidget)
    calls = []
    widget._input_panel = types.SimpleNamespace(
        set_location_source=lambda address, length: calls.append((address, length))
    )

    widget.set_location_source(0x500000, 0x40)

    assert calls == [(0x500000, 0x40)]


def test_plugin_population_uses_public_widget_api(monkeypatch):
    _stub_plugin_imports(monkeypatch)
    module = _load_module("testable_plugin", "ida_cyberchef/plugin/__init__.py")
    calls = []
    form = types.SimpleNamespace(
        w=types.SimpleNamespace(
            set_location_source=lambda address, length: calls.append((address, length))
        )
    )

    module._populate_widget_from_selection(form, 0x600000, 0x80)

    assert calls == [(0x600000, 0x80)]
