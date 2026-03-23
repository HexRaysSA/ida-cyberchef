"""Tests for shared schema normalization helpers."""

from ida_cyberchef.core.operation_registry import OperationRegistry
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
