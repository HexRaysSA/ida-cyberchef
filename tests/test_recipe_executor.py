from ida_cyberchef.core.output_model import OutputKind, TypedOutput
from ida_cyberchef.core.recipe_executor import RecipeExecutor, StepResult


def test_execute_single_operation():
    executor = RecipeExecutor()

    recipe = [{"operation": "To Hex", "args": {}}]
    results = executor.execute_recipe(b"hello", recipe)

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].data is not None
    assert results[0].error is None


def test_execute_chained_operations():
    executor = RecipeExecutor()

    recipe = [
        {"operation": "To Hex", "args": {}},
        {"operation": "To Upper case", "args": {}},
    ]
    results = executor.execute_recipe(b"test", recipe)

    assert len(results) == 2
    assert all(r.success for r in results)


def test_execution_stops_on_error():
    executor = RecipeExecutor()

    recipe = [
        {"operation": "To Hex", "args": {}},
        {"operation": "InvalidOp", "args": {}},
        {"operation": "To Upper case", "args": {}},
    ]
    results = executor.execute_recipe(b"test", recipe)

    assert len(results) == 2
    assert results[0].success is True
    assert results[1].success is False
    assert results[1].error is not None


def test_empty_recipe_returns_empty_list():
    executor = RecipeExecutor()

    recipe: list[dict[str, object]] = []
    results = executor.execute_recipe(b"hello", recipe)

    assert len(results) == 0


def test_step_result_holds_typed_output():
    output = TypedOutput(kind=OutputKind.TEXT, value="hello world")
    result = StepResult(success=True, data=output, error=None)
    assert result.data is output
    assert result.data.kind == OutputKind.TEXT
    assert result.data.value == "hello world"


def test_recipe_executor_wraps_string_output():
    """Verify RecipeExecutor wraps str output as TypedOutput(TEXT)."""
    executor = RecipeExecutor()
    recipe = [{"operation": "To Base64", "args": {}}]
    results = executor.execute_recipe(b"test", recipe)

    assert len(results) == 1
    assert results[0].success
    assert isinstance(results[0].data, TypedOutput)
    assert results[0].data.kind == OutputKind.TEXT
    assert results[0].data.value == "dGVzdA=="


def test_recipe_executor_wraps_bytes_output():
    """Verify RecipeExecutor wraps bytes output as TypedOutput(BYTES)."""
    executor = RecipeExecutor()
    recipe = [{"operation": "From Base64", "args": {}}]
    results = executor.execute_recipe(b"dGVzdA==", recipe)

    assert len(results) == 1
    assert results[0].success
    assert isinstance(results[0].data, TypedOutput)
    assert results[0].data.kind == OutputKind.BYTES
    assert results[0].data.value == b"test"
