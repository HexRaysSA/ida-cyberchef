"""Tests for LocationInputWidget."""

from ida_cyberchef.widgets.location_input_widget import LocationInputWidget


def test_location_widget_has_address_field(qtbot):
    """LocationInputWidget should have address QLineEdit with proper placeholder."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    assert widget._address_edit is not None
    assert widget._address_edit.placeholderText() == "0x00000000"


def test_location_widget_has_length_default(qtbot):
    """LocationInputWidget should have length QLineEdit with default value."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    assert widget._length_edit is not None
    assert widget._length_edit.text() == "256"


def test_location_widget_emits_signal_on_valid_input(qtbot):
    """LocationInputWidget should emit location_changed signal with parsed values."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    with qtbot.waitSignal(widget.location_changed, timeout=1000) as blocker:
        widget._address_edit.setText("0x401000")
        widget._length_edit.setText("128")
        widget._debounce_timer.timeout.emit()

    assert blocker.args == [0x401000, 128]


def test_location_widget_no_signal_on_invalid_address(qtbot):
    """LocationInputWidget should not emit when address is invalid."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    received = []
    widget.location_changed.connect(lambda a, l: received.append((a, l)))

    widget._address_edit.setText("not_hex")
    widget._length_edit.setText("128")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_no_signal_on_invalid_length(qtbot):
    """LocationInputWidget should not emit when length is invalid."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    received = []
    widget.location_changed.connect(lambda a, l: received.append((a, l)))

    widget._address_edit.setText("0x401000")
    widget._length_edit.setText("abc")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_no_signal_on_zero_length(qtbot):
    """LocationInputWidget should not emit when length is zero or negative."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    received = []
    widget.location_changed.connect(lambda a, l: received.append((a, l)))

    widget._address_edit.setText("0x401000")
    widget._length_edit.setText("0")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_emits_with_default_length(qtbot):
    """LocationInputWidget should emit using default length when only address is set."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    with qtbot.waitSignal(widget.location_changed, timeout=1000) as blocker:
        widget._address_edit.setText("0x401000")
        widget._debounce_timer.timeout.emit()

    assert blocker.args == [0x401000, 256]


def test_location_widget_invalid_address_style(qtbot):
    """LocationInputWidget should show red border on invalid address."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    widget._address_edit.setText("not_hex")
    widget._length_edit.setText("128")
    widget._debounce_timer.timeout.emit()

    assert "red" in widget._address_edit.styleSheet()
    assert "red" not in widget._length_edit.styleSheet()
