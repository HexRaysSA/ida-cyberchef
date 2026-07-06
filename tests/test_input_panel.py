import pytest

from ida_cyberchef.qt_models.input_model import InputModel, InputSource
from ida_cyberchef.widgets.input_panel import InputPanel


@pytest.fixture
def input_panel_with_ida(qtbot, monkeypatch):
    """Create InputPanel with IDA_AVAILABLE = True."""
    import ida_cyberchef.widgets.input_panel as panel_module

    monkeypatch.setattr(panel_module, "IDA_AVAILABLE", True)

    model = InputModel()
    panel = InputPanel(model)
    qtbot.addWidget(panel)
    return panel, model


def test_input_panel_has_from_location_radio(input_panel_with_ida):
    panel, _model = input_panel_with_ida
    assert panel._location_radio is not None
    assert panel._location_radio.text() == "From Location"


def test_input_panel_shows_location_widget_when_from_location_selected(
    input_panel_with_ida,
):
    panel, _model = input_panel_with_ida
    assert panel._location_widget is not None
    assert not panel._location_widget.isVisible()

    panel.show()
    panel._location_radio.setChecked(True)
    panel._on_source_changed()

    assert panel._location_widget.isVisible()
    assert panel._text_area.isReadOnly()


def test_input_panel_set_location_source_updates_ui_and_model(input_panel_with_ida):
    panel, model = input_panel_with_ida
    panel.show()

    panel.set_location_source(0x401000, 128)

    assert panel._location_radio.isChecked()
    assert panel._location_widget.isVisible()
    assert panel._text_area.isReadOnly()
    assert model.get_input_source() == InputSource.FROM_LOCATION
    assert model.get_location_address() == 0x401000
    assert model.get_location_length() == 128
    assert panel._location_widget._address_edit.text() == "0x00401000"
    assert panel._location_widget._length_edit.text() == "128"


def test_input_panel_clears_preview_when_selection_data_is_cleared(
    input_panel_with_ida,
):
    panel, model = input_panel_with_ida
    panel.show()

    panel._selection_radio.setChecked(True)
    panel._on_source_changed()

    model.set_external_data(b"hello", address=0x401000)
    assert panel._text_area.toPlainText()

    model.clear_external_data()
    assert panel._text_area.toPlainText() == ""


def test_input_panel_marks_invalid_manual_input(qtbot):
    model = InputModel()
    panel = InputPanel(model)
    qtbot.addWidget(panel)
    panel.show()

    panel._format_combo.setCurrentText("Hex String")
    panel._text_area.setPlainText("zz")

    qtbot.waitUntil(lambda: panel._validation_label.isVisible())

    assert panel._validation_label.text()
    assert "border" in panel._text_area.styleSheet()

    panel._text_area.setPlainText("41")

    qtbot.waitUntil(lambda: not panel._validation_label.isVisible())

    assert panel._validation_label.text() == ""
    assert "border" not in panel._text_area.styleSheet()
