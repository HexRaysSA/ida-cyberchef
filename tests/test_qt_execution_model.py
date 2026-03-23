from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel
from ida_cyberchef.qt_models.recipe_model import RecipeModel


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
