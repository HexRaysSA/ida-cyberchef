"""Tests for OperationStepWidget."""

from ida_cyberchef.core.output_model import OutputKind, TypedOutput
from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.qt_models.schema_adapter import normalise_operation_view_model
from ida_cyberchef.widgets.operation_step_widget import OperationStepWidget


def test_option_dropdown_shows_all_choices(qtbot):
    """Option dropdown should show all choices from schema, not just selected value."""
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    # Simulate saved step with "Output differential" selected
    op_with_saved = xor_op.copy()
    for arg in op_with_saved["args"]:
        if arg["name"] == "Scheme":
            arg["saved_value"] = "Output differential"

    widget = OperationStepWidget(0, op_with_saved)
    qtbot.addWidget(widget)

    # Find the Scheme dropdown
    scheme_widget = widget._arg_widgets["Scheme"]

    # Should have all 4 options
    assert scheme_widget.count() == 4
    assert scheme_widget.itemText(0) == "Standard"
    assert scheme_widget.itemText(1) == "Input differential"
    assert scheme_widget.itemText(2) == "Output differential"
    assert scheme_widget.itemText(3) == "Cascade"

    # Should have "Output differential" selected
    assert scheme_widget.currentText() == "Output differential"


def test_togglestring_dict_value_displays_correctly(qtbot):
    """ToggleString with dict value should extract string part for display."""
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    # Simulate saved step with toggleString dict value
    op_with_saved = xor_op.copy()
    for arg in op_with_saved["args"]:
        if arg["name"] == "Key":
            arg["value"] = {"string": "deadbeef", "option": "Hex"}

    widget = OperationStepWidget(0, op_with_saved)
    qtbot.addWidget(widget)

    # Find the Key input (it's a container with properties)
    key_container = widget._arg_widgets["Key"]
    value_input = key_container.property("value_input")
    format_combo = key_container.property("format_combo")

    # Should extract "deadbeef" for input, "Hex" for dropdown
    assert value_input.text() == "deadbeef"
    assert format_combo.currentText() == "Hex"


def test_enigma_editable_option_shows_label_but_returns_runtime_value(qtbot):
    """Editable option widgets should render names while storing runtime values."""
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    widget = OperationStepWidget(
        0,
        normalise_operation_view_model(
            enigma_op,
            {
                "Model": "4-rotor",
                "Right-hand rotor": "BDFHJLCPRTXVZNYEIWGAKMUSQO<W",
                "Strict output": False,
            },
        ),
    )
    qtbot.addWidget(widget)

    rotor_widget = widget._arg_widgets["Right-hand rotor"]
    model_widget = widget._arg_widgets["Model"]
    strict_output_widget = widget._arg_widgets["Strict output"]

    assert rotor_widget.currentText() == "III"
    assert model_widget.currentText() == "4-rotor"
    assert strict_output_widget.isChecked() is False

    current_args = widget.get_current_args()
    assert current_args["Right-hand rotor"] == "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
    assert current_args["Model"] == "4-rotor"
    assert current_args["Strict output"] is False


def test_populate_option_shows_readable_choice_and_preserves_runtime_value(qtbot):
    """populateOption widgets should show labels while round-tripping saved values."""
    registry = OperationRegistry()
    datetime_op = registry.find_operation("Translate DateTime Format")
    assert datetime_op is not None

    widget = OperationStepWidget(
        0,
        normalise_operation_view_model(
            datetime_op,
            {"Built in formats": "YYYY-MM-DD HH:mm:ss"},
        ),
    )
    qtbot.addWidget(widget)

    preset_widget = widget._arg_widgets["Built in formats"]

    assert preset_widget.currentText() == "International date and time"
    assert widget.get_current_args()["Built in formats"] == "YYYY-MM-DD HH:mm:ss"


def test_populate_multi_option_restores_saved_selection(qtbot):
    """populateMultiOption widgets should restore saved preset names."""
    registry = OperationRegistry()
    bombe_op = registry.find_operation("Multiple Bombe")
    assert bombe_op is not None

    widget = OperationStepWidget(
        0,
        normalise_operation_view_model(
            bombe_op,
            {"Standard Enigmas": "German Service Enigma (Fourth - 4 rotor)"},
        ),
    )
    qtbot.addWidget(widget)

    preset_widget = widget._arg_widgets["Standard Enigmas"]

    assert preset_widget.currentText() == "German Service Enigma (Fourth - 4 rotor)"
    assert (
        widget.get_current_args()["Standard Enigmas"]
        == "German Service Enigma (Fourth - 4 rotor)"
    )


def test_clear_preview_clears_text_without_collapsing_preview(qtbot):
    """clear_preview should remove stale text without changing expansion state."""
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    widget = OperationStepWidget(0, xor_op)
    qtbot.addWidget(widget)

    widget._on_preview_clicked()
    widget.set_preview_data(TypedOutput(kind=OutputKind.TEXT, value="stale preview"))

    widget.clear_preview()

    assert widget._preview_visible is True
    assert widget._preview_widget.toPlainText() == ""u


def test_arg_selector_updates_dependent_row_visibility(qtbot):
    """argSelector widgets should show and hide dependent rows."""
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    widget = OperationStepWidget(0, normalise_operation_view_model(enigma_op))
    qtbot.addWidget(widget)

    model_widget = widget._arg_widgets["Model"]
    leftmost_rotor_widget = widget._arg_widgets["Left-most (4th) rotor"]

    assert model_widget.currentText() == "3-rotor"
    assert leftmost_rotor_widget.isHidden() is True

    model_widget.setCurrentText("4-rotor")

    assert leftmost_rotor_widget.isHidden() is False
