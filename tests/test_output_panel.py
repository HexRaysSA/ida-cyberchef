"""Tests for OutputPanel format-awareness."""

from unittest.mock import MagicMock

from ida_cyberchef.core.output_model import OutputKind, TypedOutput
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
    from ida_cyberchef.qt_models.input_model import InputModel, InputSource
    from ida_cyberchef.widgets.output_panel import OutputPanel

    input_model = InputModel()
    input_model.set_manual_text("")
    exec_model = ExecutionModel(input_model, MagicMock())
    exec_model._recipe_model = MagicMock()

    panel = OutputPanel(exec_model, input_model, show_ida_buttons=show_ida_buttons)
    qtbot.addWidget(panel)
    return panel, input_model


def test_format_output_bytes_hex_dump(qtbot):
    panel, _ = _make_panel(qtbot)

    output = TypedOutput(kind=OutputKind.BYTES, value=b"\xde\xad\xbe\xef")
    result = panel._format_output(output, "Hex Dump")
    assert "de" in result.lower()
    assert "ad" in result.lower()


def test_format_output_json_pretty(qtbot):
    import json

    panel, _ = _make_panel(qtbot)

    data = {"key": "value", "num": 42}
    output = TypedOutput(kind=OutputKind.JSON, value=data)
    result = panel._format_output(output, "Pretty JSON")
    parsed = json.loads(result)
    assert parsed == data
    assert "\n" in result


def test_format_output_json_compact(qtbot):
    import json

    panel, _ = _make_panel(qtbot)

    data = {"key": "value"}
    output = TypedOutput(kind=OutputKind.JSON, value=data)
    result = panel._format_output(output, "Compact JSON")
    assert "\n" not in result
    assert json.loads(result) == data


def test_format_output_file_info(qtbot):
    panel, _ = _make_panel(qtbot)

    file_value = {"name": "test.bin", "type": "application/octet-stream", "data": b"\x00" * 10}
    output = TypedOutput(kind=OutputKind.FILE, value=file_value)
    result = panel._format_output(output, "File Info")
    assert "test.bin" in result
    assert "10" in result


def test_format_output_file_list_summary(qtbot):
    panel, _ = _make_panel(qtbot)

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

    panel, input_model = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.TEXT, value="hello")
    panel._update_button_states()

    assert not panel._copy_db_button.isEnabled()


def test_update_button_states_copy_db_enabled_for_bytes_with_address(qtbot):
    from ida_cyberchef.qt_models.input_model import InputSource

    panel, input_model = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.BYTES, value=b"\xde\xad")
    panel._update_button_states()

    assert panel._copy_db_button.isEnabled()


def test_update_button_states_copy_db_disabled_for_json(qtbot):
    from ida_cyberchef.qt_models.input_model import InputSource

    panel, input_model = _make_panel(qtbot, show_ida_buttons=True)
    input_model.set_external_data(b"\xde\xad", address=0x1000)
    input_model.set_input_source(InputSource.FROM_SELECTION)

    panel._current_output = TypedOutput(kind=OutputKind.JSON, value={"x": 1})
    panel._update_button_states()

    assert not panel._copy_db_button.isEnabled()
