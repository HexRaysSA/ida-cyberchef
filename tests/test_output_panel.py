"""Tests for OutputPanel format-awareness."""

from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.core.output_model import OutputKind, TypedOutput
from ida_cyberchef.qt_models.recipe_model import RecipeModel
from ida_cyberchef.widgets.output_panel import _FORMATS_FOR_KIND


def test_formats_for_kind_bytes():
    formats = _FORMATS_FOR_KIND[OutputKind.BYTES]
    assert "Hex Dump" in formats
    assert "Text" in formats
    assert len(formats) > 1


def test_formats_for_kind_text_only_text():
    formats = _FORMATS_FOR_KIND[OutputKind.TEXT]
    assert formats == ["Text"]


def test_formats_for_kind_json_has_pretty_and_compact():
    formats = _FORMATS_FOR_KIND[OutputKind.JSON]
    assert "Pretty JSON" in formats
    assert "Compact JSON" in formats


def test_formats_for_kind_file():
    formats = _FORMATS_FOR_KIND[OutputKind.FILE]
    assert "Hex Dump" in formats
    assert "File Info" in formats


def test_formats_for_kind_file_list():
    formats = _FORMATS_FOR_KIND[OutputKind.FILE_LIST]
    assert formats == ["File List Summary"]


def test_formats_for_kind_error_is_empty():
    formats = _FORMATS_FOR_KIND[OutputKind.ERROR]
    assert formats == []


def _make_panel(qtbot, show_ida_buttons=False):
    from ida_cyberchef.qt_models.execution_model import ExecutionModel
    from ida_cyberchef.qt_models.input_model import InputModel
    from ida_cyberchef.widgets.output_panel import OutputPanel

    input_model = InputModel()
    input_model.set_manual_text("")
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    panel = OutputPanel(exec_model, input_model, show_ida_buttons=show_ida_buttons)
    qtbot.addWidget(panel)
    return panel, input_model, recipe_model, exec_model


def _run_execution(qtbot, exec_model):
    with qtbot.waitSignal(exec_model.execution_completed, timeout=2000):
        exec_model.schedule_execution()


def test_format_output_bytes_hex_dump(qtbot):
    panel, _, _, _ = _make_panel(qtbot)

    output = TypedOutput(kind=OutputKind.BYTES, value=b"\xde\xad\xbe\xef")
    result = panel._format_output(output, "Hex Dump")
    assert "de" in result.lower()
    assert "ad" in result.lower()


def test_format_output_json_pretty(qtbot):
    import json

    panel, _, _, _ = _make_panel(qtbot)

    data = {"key": "value", "num": 42}
    output = TypedOutput(kind=OutputKind.JSON, value=data)
    result = panel._format_output(output, "Pretty JSON")
    parsed = json.loads(result)
    assert parsed == data
    assert "\n" in result


def test_format_output_json_compact(qtbot):
    import json

    panel, _, _, _ = _make_panel(qtbot)

    data = {"key": "value"}
    output = TypedOutput(kind=OutputKind.JSON, value=data)
    result = panel._format_output(output, "Compact JSON")
    assert "\n" not in result
    assert json.loads(result) == data


def test_format_output_file_info(qtbot):
    panel, _, _, _ = _make_panel(qtbot)

    file_value = {"name": "test.bin", "type": "application/octet-stream", "data": b"\x00" * 10}
    output = TypedOutput(kind=OutputKind.FILE, value=file_value)
    result = panel._format_output(output, "File Info")
    assert "test.bin" in result
    assert "10" in result


def test_format_output_file_list_summary(qtbot):
    panel, _, _, _ = _make_panel(qtbot)

    files = [
        {"name": "a.bin", "type": "", "data": b"\x00\x01"},
        {"name": "b.bin", "type": "", "data": b"\x02\x03\x04"},
    ]
    output = TypedOutput(kind=OutputKind.FILE_LIST, value=files)
    result = panel._format_output(output, "File List Summary")
    assert "a.bin" in result
    assert "b.bin" in result
    assert "2 bytes" in result
    assert "3 bytes" in result


def test_update_button_states_copy_db_disabled_for_text(qtbot):
    from ida_cyberchef.qt_models.input_model import InputSource

    panel, input_model, _, _ = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.TEXT, value="hello")
    panel._update_button_states()

    assert not panel._copy_db_button.isEnabled()


def test_update_button_states_copy_db_enabled_for_bytes_with_address(qtbot):
    from ida_cyberchef.qt_models.input_model import InputSource

    panel, input_model, _, _ = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.BYTES, value=b"\xde\xad")
    panel._update_button_states()

    assert panel._copy_db_button.isEnabled()


def test_update_button_states_copy_db_disabled_for_json(qtbot):
    from ida_cyberchef.qt_models.input_model import InputSource

    panel, input_model, _, _ = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.JSON, value={"x": 1})
    panel._update_button_states()

    assert not panel._copy_db_button.isEnabled()


def test_update_output_preserves_selected_format_for_same_output_kind(qtbot):
    panel, input_model, _, exec_model = _make_panel(qtbot)

    input_model.set_input_format(InputFormat.HEX_STRING)
    input_model.set_manual_text("de ad")
    _run_execution(qtbot, exec_model)
    panel._output_format_combo.setCurrentText("Hex String (Spaced)")

    input_model.set_manual_text("be ef")
    _run_execution(qtbot, exec_model)

    assert panel._output_format_combo.currentText() == "Hex String (Spaced)"
    assert panel._output_display.toPlainText() == "be ef"


def test_update_output_resets_format_when_output_kind_changes(qtbot):
    panel, input_model, recipe_model, exec_model = _make_panel(qtbot)

    input_model.set_input_format(InputFormat.HEX_STRING)
    input_model.set_manual_text("de ad")
    _run_execution(qtbot, exec_model)
    panel._output_format_combo.setCurrentText("Hex String (Spaced)")

    recipe_model.add_operation("To Base64", {})
    _run_execution(qtbot, exec_model)

    assert panel._output_format_combo.currentText() == "Text"
    assert panel._output_display.toPlainText() == "3q0="


def test_update_output_auto_selects_default_again_after_clear(qtbot):
    panel, input_model, _, exec_model = _make_panel(qtbot)

    input_model.set_input_format(InputFormat.HEX_STRING)
    input_model.set_manual_text("de ad")
    _run_execution(qtbot, exec_model)
    panel._output_format_combo.setCurrentText("Hex String (Spaced)")

    input_model.set_manual_text("not hex")
    _run_execution(qtbot, exec_model)

    input_model.set_manual_text("be ef")
    _run_execution(qtbot, exec_model)

    assert panel._output_format_combo.currentText() == "Hex Dump"
