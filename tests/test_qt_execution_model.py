from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel
from ida_cyberchef.qt_models.recipe_model import RecipeModel
from ida_cyberchef.widgets.recipe_panel import RecipePanel


def test_create_execution_model():
    input_model = InputModel()
    recipe_model = RecipeModel()

    exec_model = ExecutionModel(input_model, recipe_model)
    assert exec_model is not None


def test_execution_completed_signal(qtbot):
    input_model = InputModel()
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    input_model.set_manual_text("Hello")
    recipe_model.add_operation("To Hex", {})

    with qtbot.waitSignal(exec_model.execution_completed, timeout=2000):
        exec_model.schedule_execution()


def test_get_execution_results(qtbot):
    input_model = InputModel()
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    input_model.set_manual_text("Hello")
    recipe_model.add_operation("To Hex", {})

    with qtbot.waitSignal(exec_model.execution_completed, timeout=2000):
        exec_model.schedule_execution()

    results = exec_model.get_results()
    assert len(results) == 1
    assert results[0].success is True


def test_debouncing(qtbot):
    input_model = InputModel()
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    input_model.set_manual_text("A")

    signals = []
    exec_model.execution_completed.connect(lambda: signals.append(1))

    input_model.set_manual_text("B")
    input_model.set_manual_text("C")

    qtbot.wait(200)

    # Should get 1-2 signals: initial "A" may still be pending when we connect,
    # then "B" and "C" are debounced into a single execution
    assert 1 <= len(signals) <= 2


def test_empty_recipe_passes_through_input(qtbot):
    input_model = InputModel()
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    test_data = "Hello World"
    input_model.set_manual_text(test_data)

    with qtbot.waitSignal(exec_model.execution_completed, timeout=2000):
        exec_model.schedule_execution()

    from ida_cyberchef.core.output_model import OutputKind

    results = exec_model.get_results()
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].data is not None
    assert results[0].data.kind == OutputKind.BYTES
    assert results[0].data.value == test_data.encode("utf-8")
    assert results[0].error is None

    final_result = exec_model.get_final_result()
    assert final_result is not None
    assert final_result.data is not None
    assert final_result.data.value == test_data.encode("utf-8")

def test_invalid_manual_input_does_not_passthrough_empty_recipe(qtbot):
    from ida_cyberchef.core.input_parser import InputFormat

    input_model = InputModel()
    recipe_model = RecipeModel()
    exec_model = ExecutionModel(input_model, recipe_model, debounce_ms=50)

    input_model.set_input_format(InputFormat.HEX_STRING)
    input_model.set_manual_text("zz")

    with qtbot.waitSignal(exec_model.execution_completed, timeout=2000):
        exec_model.schedule_execution()

    assert input_model.get_parse_error() is not None
    assert exec_model.get_results() == []
    assert exec_model.get_final_result() is None


def _build_recipe_panel(qtbot, input_text, operations, input_format=InputFormat.TEXT_UTF8):
    """Build a recipe panel and return input, recipe, execution models, and panel."""
    input_model = InputModel()
    input_model.set_input_format(input_format)
    input_model.set_manual_text(input_text)

    recipe_model = RecipeModel()
    for operation, args in operations:
        recipe_model.add_operation(operation, args)

    execution_model = ExecutionModel(input_model, recipe_model, debounce_ms=0)
    panel = RecipePanel(recipe_model, execution_model, OperationRegistry())
    qtbot.addWidget(panel)
    panel._refresh_display()

    assert len(panel._step_widgets) == len(operations)
    return input_model, recipe_model, execution_model, panel


def _execute_recipe_panel(qtbot, execution_model):
    with qtbot.waitSignal(execution_model.execution_completed, timeout=2000):
        execution_model.schedule_execution()


def test_recipe_panel_clears_later_stale_preview_and_error(qtbot):
    input_model, _, execution_model, panel = _build_recipe_panel(
        qtbot,
        input_text="104 105",
        operations=[("From Decimal", {}), ("To Base64", {})],
    )
    _execute_recipe_panel(qtbot, execution_model)

    first_widget, second_widget = panel._step_widgets
    assert first_widget._preview_widget.toPlainText() != ""
    assert second_widget._preview_widget.toPlainText() == "aGk="

    with qtbot.waitSignal(execution_model.execution_completed, timeout=2000):
        input_model.set_manual_text("abc")

    assert first_widget._error_visible is True
    assert first_widget._error_label.text() == "Error: cannot convert float NaN to integer"
    assert second_widget._preview_widget.toPlainText() == ""
    assert second_widget._error_visible is False


def test_recipe_panel_clears_stale_state_after_recipe_edit(qtbot):
    _, recipe_model, execution_model, panel = _build_recipe_panel(
        qtbot,
        input_text="104 105",
        operations=[("From Decimal", {"Delimiter": "Space"}), ("To Base64", {})],
    )
    _execute_recipe_panel(qtbot, execution_model)

    first_widget, second_widget = panel._step_widgets
    assert first_widget._preview_widget.toPlainText() != ""
    assert second_widget._preview_widget.toPlainText() == "aGk="

    with qtbot.waitSignal(execution_model.execution_completed, timeout=2000):
        recipe_model.update_operation_args(0, {"Delimiter": "None"})

    assert first_widget._error_visible is True
    assert (
        first_widget._error_label.text()
        == "Error: 'float' object cannot be interpreted as an integer"
    )
    assert second_widget._preview_widget.toPlainText() == ""
    assert second_widget._error_visible is False


def test_recipe_panel_clears_all_stale_state_for_empty_results(qtbot):
    input_model, _, execution_model, panel = _build_recipe_panel(
        qtbot,
        input_text="hello",
        operations=[("To Base64", {}), ("From Decimal", {"Delimiter": "None"})],
    )
    _execute_recipe_panel(qtbot, execution_model)

    first_widget, second_widget = panel._step_widgets
    assert first_widget._preview_widget.toPlainText() != ""
    assert second_widget._error_visible is True

    with qtbot.waitSignal(execution_model.execution_completed, timeout=2000):
        input_model.set_input_format(InputFormat.HEX_STRING)

    for widget in panel._step_widgets:
        assert widget._preview_widget.toPlainText() == ""
        assert widget._error_visible is False
