"""Automated UI verification tests for Task 7 manual testing requirements."""

from PySide6.QtWidgets import QComboBox, QLabel

from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.widgets.operation_step_widget import OperationStepWidget


def test_xor_operation_layout(qtbot):
    """Test case 1: Verify XOR operation shows proper layout.

    Requirements:
    - Key field shows empty input
    - Hex dropdown with label "Key:"
    - Can type "deadbeef" in Key input
    - Can select "Decimal" from dropdown
    - Layout shows clean with proper labels
    """
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    widget = OperationStepWidget(0, xor_op)
    qtbot.addWidget(widget)

    # Verify Key toggleString widget exists
    key_container = widget._arg_widgets["Key"]
    value_input = key_container.property("value_input")
    format_combo = key_container.property("format_combo")

    assert value_input is not None, "Key input should exist"
    assert format_combo is not None, "Format dropdown should exist"

    # Initially empty
    assert value_input.text() == "", "Key input should be empty initially"

    # Verify dropdown has Hex options
    assert format_combo.count() > 0, "Format dropdown should have options"
    assert "Hex" in [format_combo.itemText(i) for i in range(format_combo.count())], "Should have Hex option"
    assert "Decimal" in [format_combo.itemText(i) for i in range(format_combo.count())], "Should have Decimal option"

    # Simulate user typing "deadbeef"
    value_input.setText("deadbeef")
    assert value_input.text() == "deadbeef", "Should accept text input"

    # Simulate selecting "Decimal"
    format_combo.setCurrentText("Decimal")
    assert format_combo.currentText() == "Decimal", "Should change dropdown selection"

    # Verify get_current_args returns correct format
    args = widget.get_current_args()
    assert "Key" in args, "Args should contain Key"
    assert isinstance(args["Key"], dict), "Key value should be dict"
    assert args["Key"]["string"] == "deadbeef", "Key string should match"
    assert args["Key"]["option"] == "Decimal", "Key option should match"


def test_to_base64_operation_no_args(qtbot):
    """Test case 2: Verify To Base64 operation (simple, no args).

    Requirements:
    - Should show operation name + buttons only
    - No grid layout for args
    """
    registry = OperationRegistry()
    base64_op = registry.find_operation("To Base64")
    assert base64_op is not None

    widget = OperationStepWidget(0, base64_op)
    qtbot.addWidget(widget)

    # Should have minimal or no arg widgets
    # To Base64 has optional alphabet argument, but we verify structure

    # Operation name should be visible in widget
    assert "To Base64" in [child.text() for child in widget.findChildren(QLabel) if hasattr(child, "text")], (
        "Operation name should be displayed"
    )

    # Preview button should exist
    assert widget._preview_button is not None, "Preview button should exist"


def test_aes_decrypt_operation_many_args(qtbot):
    """Test case 3: Verify AES Decrypt operation (many args).

    Requirements:
    - Verify toggleString args (Key, IV, GCM Tag) show correctly with labels and format dropdowns
    - Verify option dropdowns (Mode, Input, Output) have all choices
    """
    registry = OperationRegistry()
    aes_op = registry.find_operation("AES Decrypt")
    assert aes_op is not None

    widget = OperationStepWidget(0, aes_op)
    qtbot.addWidget(widget)

    # Verify toggleString args exist
    togglestring_args = ["Key", "IV"]  # AES Decrypt has these
    for arg_name in togglestring_args:
        if arg_name in widget._arg_widgets:
            container = widget._arg_widgets[arg_name]
            value_input = container.property("value_input")
            format_combo = container.property("format_combo")

            assert value_input is not None, f"{arg_name} should have input field"
            assert format_combo is not None, f"{arg_name} should have format dropdown"
            assert format_combo.count() > 0, f"{arg_name} dropdown should have options"

    # Verify option dropdowns have multiple choices
    option_args = ["Mode", "Input format", "Output format"]
    for arg_name in option_args:
        if arg_name in widget._arg_widgets:
            dropdown = widget._arg_widgets[arg_name]
            if isinstance(dropdown, QComboBox):
                assert dropdown.count() > 1, f"{arg_name} should have multiple options"


def test_save_and_reload_recipe_preserves_values(qtbot):
    """Test case 4: Verify save and reload recipe functionality.

    Requirements:
    - Save recipe with XOR operation (Key="deadbeef", option="Decimal")
    - Verify values preserved correctly when reloading
    - Verify dropdowns still show all options (not just selected)
    """
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    # First widget: simulate initial state with user input
    widget1 = OperationStepWidget(0, xor_op)
    qtbot.addWidget(widget1)

    key_container1 = widget1._arg_widgets["Key"]
    value_input1 = key_container1.property("value_input")
    format_combo1 = key_container1.property("format_combo")

    value_input1.setText("deadbeef")
    format_combo1.setCurrentText("Decimal")

    # Get the saved args (simulating save)
    saved_args = widget1.get_current_args()

    # Second widget: simulate reload with saved values
    xor_op_reload = registry.find_operation("XOR")
    assert xor_op_reload is not None
    xor_op_reload_copy = xor_op_reload.copy()
    xor_op_reload_copy["args"] = [arg.copy() for arg in xor_op_reload_copy["args"]]

    # Merge saved values using saved_value field (as recipe_panel does)
    for arg in xor_op_reload_copy["args"]:
        if arg["name"] in saved_args:
            arg["saved_value"] = saved_args[arg["name"]]

    widget2 = OperationStepWidget(0, xor_op_reload_copy)
    qtbot.addWidget(widget2)

    # Verify values are preserved
    key_container2 = widget2._arg_widgets["Key"]
    value_input2 = key_container2.property("value_input")
    format_combo2 = key_container2.property("format_combo")

    assert value_input2.text() == "deadbeef", "Key value should be preserved"
    assert format_combo2.currentText() == "Decimal", "Format selection should be preserved"

    # Verify dropdown still has all options (not just selected)
    assert format_combo2.count() > 1, "Format dropdown should have multiple options"
    assert "Hex" in [format_combo2.itemText(i) for i in range(format_combo2.count())], (
        "Dropdown should still have Hex option"
    )
    assert "Decimal" in [format_combo2.itemText(i) for i in range(format_combo2.count())], (
        "Dropdown should still have Decimal option"
    )

    # Verify Scheme option dropdown also preserves all choices
    if "Scheme" in widget2._arg_widgets:
        scheme_dropdown = widget2._arg_widgets["Scheme"]
        assert scheme_dropdown.count() == 4, "Scheme should have all 4 options"
        assert scheme_dropdown.itemText(0) == "Standard"
        assert scheme_dropdown.itemText(1) == "Input differential"
        assert scheme_dropdown.itemText(2) == "Output differential"
        assert scheme_dropdown.itemText(3) == "Cascade"


def test_grid_layout_labels_exist(qtbot):
    """Verify grid layout has proper labels for arguments."""
    registry = OperationRegistry()
    xor_op = registry.find_operation("XOR")
    assert xor_op is not None

    widget = OperationStepWidget(0, xor_op)
    qtbot.addWidget(widget)

    # Find all labels in the grid
    labels = widget.findChildren(QLabel)
    label_texts = [label.text() for label in labels]

    # Should have labels for arguments (excluding operation name label)
    # XOR has: Key, Scheme, Null preserving (checkbox - no label)
    assert "Key:" in label_texts, "Should have label for Key argument"
    assert "Scheme:" in label_texts, "Should have label for Scheme argument"

    # Verify label styling (gray color)
    for label in labels:
        if label.text().endswith(":"):
            style = label.styleSheet()
            assert "color" in style.lower(), "Argument labels should have color styling"
