"""Tests for shared schema normalization helpers."""

from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.core.schema_adapter import (
    get_argument_default_value,
    get_dependent_args,
    get_display_items,
    get_display_label_for_value,
    get_option_value_for_display,
)
from ida_cyberchef.qt_models.schema_adapter import (
    get_operation_default_args,
    normalise_operation_view_model,
)


def test_get_operation_default_args_uses_default_index_and_runtime_values():
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    defaults = get_operation_default_args(enigma_op)

    assert defaults["Model"] == "3-rotor"
    assert defaults["Middle rotor"] == "AJDKSIRUXBLHWTMCQGZNPYFVOE<F"
    assert defaults["Right-hand rotor"] == "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
    assert defaults["Strict output"] is True


def test_normalise_operation_view_model_preserves_saved_falsy_values():
    registry = OperationRegistry()
    image_op = registry.find_operation("Add Text To Image")
    assert image_op is not None

    operation_view = normalise_operation_view_model(
        image_op,
        {"Size": 0, "Red": 0},
    )
    args_by_name = {arg.name: arg for arg in operation_view["args"]}

    assert args_by_name["Size"].value == 0
    assert args_by_name["Red"].value == 0


def test_normalise_operation_view_model_preserves_editable_option_label_mapping():
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    runtime_value = "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
    operation_view = normalise_operation_view_model(
        enigma_op,
        {"Right-hand rotor": runtime_value},
    )
    args_by_name = {arg.name: arg for arg in operation_view["args"]}
    right_hand_rotor = args_by_name["Right-hand rotor"]

    assert right_hand_rotor.value == runtime_value
    assert any(
        option.label == "III" and option.value == runtime_value
        for option in right_hand_rotor.options
    )


def test_shared_adapter_extracts_defaults_for_binary_and_populate_multi_option():
    assert get_argument_default_value({"type": "binaryString", "value": "\\n"}) == "\n"

    registry = OperationRegistry()
    bombe_op = registry.find_operation("Multiple Bombe")
    assert bombe_op is not None

    default_value = get_argument_default_value(bombe_op["args"][0])
    assert default_value == "German Service Enigma (First - 3 rotor)"


def test_shared_adapter_round_trips_display_labels_and_runtime_values():
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    datetime_op = registry.find_operation("Translate DateTime Format")
    assert enigma_op is not None
    assert datetime_op is not None

    rotor_arg = next(arg for arg in enigma_op["args"] if arg["name"] == "Right-hand rotor")
    preset_arg = next(
        arg for arg in datetime_op["args"] if arg["name"] == "Built in formats"
    )

    assert "III" in get_display_items(rotor_arg)
    assert (
        get_option_value_for_display(rotor_arg, "III")
        == "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
    )
    assert (
        get_display_label_for_value(
            rotor_arg,
            "BDFHJLCPRTXVZNYEIWGAKMUSQO<W",
        )
        == "III"
    )

    assert (
        get_option_value_for_display(preset_arg, "International date and time")
        == "YYYY-MM-DD HH:mm:ss"
    )
    assert (
        get_display_label_for_value(preset_arg, "YYYY-MM-DD HH:mm:ss")
        == "International date and time"
    )


def test_shared_adapter_reports_arg_selector_dependencies():
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    model_arg = enigma_op["args"][0]

    visible_args, hidden_args = get_dependent_args(enigma_op["args"], model_arg, "3-rotor")
    assert visible_args == set()
    assert hidden_args == {
        "Left-most (4th) rotor",
        "Left-most rotor ring setting",
        "Left-most rotor initial value",
    }

    visible_args, hidden_args = get_dependent_args(enigma_op["args"], model_arg, "4-rotor")
    assert visible_args == {
        "Left-most (4th) rotor",
        "Left-most rotor ring setting",
        "Left-most rotor initial value",
    }
    assert hidden_args == set()


def test_normalise_operation_view_model_restores_saved_option_labels():
    registry = OperationRegistry()
    enigma_op = registry.find_operation("Enigma")
    assert enigma_op is not None

    operation_view = normalise_operation_view_model(
        enigma_op,
        {"Right-hand rotor": "III"},
    )
    args_by_name = {arg.name: arg for arg in operation_view["args"]}

    assert args_by_name["Right-hand rotor"].value == "BDFHJLCPRTXVZNYEIWGAKMUSQO<W"
