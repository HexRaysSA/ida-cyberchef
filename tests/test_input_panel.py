import pytest

from ida_cyberchef.qt_models.input_model import InputModel
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
    panel, model = input_panel_with_ida
    assert panel._location_radio is not None
    assert panel._location_radio.text() == "From Location"


def test_input_panel_shows_location_widget_when_from_location_selected(
    input_panel_with_ida,
):
    panel, model = input_panel_with_ida
    assert panel._location_widget is not None
    assert not panel._location_widget.isVisible()

    panel.show()
    panel._location_radio.setChecked(True)
    panel._on_source_changed()

    assert panel._location_widget.isVisible()
    assert panel._text_area.isReadOnly()
