"""Tests for LocationInputWidget."""

from ida_cyberchef.widgets.location_input_widget import (
    MODE_END_ADDRESS,
    MODE_LENGTH,
    LocationInputWidget,
)


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
    widget.location_changed.connect(lambda a, length: received.append((a, length)))

    widget._address_edit.setText("not_hex")
    widget._length_edit.setText("128")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_no_signal_on_invalid_length(qtbot):
    """LocationInputWidget should not emit when length is invalid."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    received = []
    widget.location_changed.connect(lambda a, length: received.append((a, length)))

    widget._address_edit.setText("0x401000")
    widget._length_edit.setText("abc")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_no_signal_on_zero_length(qtbot):
    """LocationInputWidget should not emit when length is zero or negative."""
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    received = []
    widget.location_changed.connect(lambda a, length: received.append((a, length)))

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


def test_location_widget_defaults_to_length_mode(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    assert widget._mode_combo.currentIndex() == MODE_LENGTH
    assert not widget._length_edit.isHidden()
    assert widget._end_addr_edit.isHidden()


def test_location_widget_end_addr_mode_emits_computed_length(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)

    with qtbot.waitSignal(widget.location_changed, timeout=1000) as blocker:
        widget._address_edit.setText("0x401000")
        widget._end_addr_edit.setText("0x401100")
        widget._debounce_timer.timeout.emit()

    assert blocker.args == [0x401000, 0x100]


def test_location_widget_end_addr_mode_toggles_visibility(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)
    assert not widget._end_addr_edit.isHidden()
    assert widget._length_edit.isHidden()

    widget._mode_combo.setCurrentIndex(MODE_LENGTH)
    assert not widget._length_edit.isHidden()
    assert widget._end_addr_edit.isHidden()


def test_location_widget_end_addr_no_signal_when_end_before_start(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)

    received = []
    widget.location_changed.connect(lambda a, length: received.append((a, length)))

    widget._address_edit.setText("0x401100")
    widget._end_addr_edit.setText("0x401000")
    widget._debounce_timer.timeout.emit()

    assert received == []
    assert "red" in widget._end_addr_edit.styleSheet()


def test_location_widget_end_addr_no_signal_when_equal(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)

    received = []
    widget.location_changed.connect(lambda a, length: received.append((a, length)))

    widget._address_edit.setText("0x401000")
    widget._end_addr_edit.setText("0x401000")
    widget._debounce_timer.timeout.emit()

    assert received == []


def test_location_widget_end_addr_invalid_shows_red(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)

    widget._address_edit.setText("0x401000")
    widget._end_addr_edit.setText("not_hex")
    widget._debounce_timer.timeout.emit()

    assert "red" in widget._end_addr_edit.styleSheet()


def test_location_widget_set_location_in_end_addr_mode(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)
    widget._mode_combo.setCurrentIndex(MODE_END_ADDRESS)

    with qtbot.waitSignal(widget.location_changed, timeout=1000) as blocker:
        widget.set_location(0x401000, 0x100)
        widget._debounce_timer.timeout.emit()

    assert widget._end_addr_edit.text() == "0x00401100"
    assert blocker.args == [0x401000, 0x100]


def test_location_widget_set_location_in_length_mode(qtbot):
    widget = LocationInputWidget()
    qtbot.addWidget(widget)

    with qtbot.waitSignal(widget.location_changed, timeout=1000) as blocker:
        widget.set_location(0x401000, 128)
        widget._debounce_timer.timeout.emit()

    assert widget._length_edit.text() == "128"
    assert blocker.args == [0x401000, 128]
