from PySide6.QtCore import QObject, Signal

from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.core.output_model import OutputKind, TypedOutput
from ida_cyberchef.core.recipe_executor import StepResult
from ida_cyberchef.qt_models.recipe_model import RecipeModel
from ida_cyberchef.widgets.recipe_panel import RecipePanel


class FakeExecutionModel(QObject):
    execution_completed = Signal()

    def __init__(self):
        super().__init__()
        self._results = []

    def set_results(self, results):
        self._results = list(results)

    def get_results(self):
        return list(self._results)

    def schedule_execution(self):
        """RecipePanel may request execution when previews are toggled."""


def _build_panel(qtbot):
    recipe_model = RecipeModel()
    execution_model = FakeExecutionModel()
    registry = OperationRegistry()
    recipe_model.add_operation("XOR", {})
    recipe_model.add_operation("XOR", {})

    panel = RecipePanel(recipe_model, execution_model, registry)
    qtbot.addWidget(panel)
    panel._refresh_display()

    assert len(panel._step_widgets) == 2
    return recipe_model, execution_model, panel


def _set_stale_preview(widget, text: str):
    if not widget._preview_visible:
        widget._on_preview_clicked()
    widget.set_preview_data(TypedOutput(kind=OutputKind.TEXT, value=text))


def test_update_results_clears_later_stale_preview_and_error(qtbot):
    _, execution_model, panel = _build_panel(qtbot)
    first_widget, second_widget = panel._step_widgets

    _set_stale_preview(first_widget, "first stale preview")
    _set_stale_preview(second_widget, "second stale preview")
    second_widget.set_error("old error")

    execution_model.set_results(
        [StepResult(success=False, data=None, error="new failure")]
    )
    execution_model.execution_completed.emit()

    assert first_widget._error_visible is True
    assert first_widget._error_label.text() == "Error: new failure"
    assert second_widget._preview_widget.toPlainText() == ""
    assert second_widget._error_visible is False


def test_update_results_clears_stale_state_after_recipe_edit(qtbot):
    recipe_model, execution_model, panel = _build_panel(qtbot)
    first_widget, second_widget = panel._step_widgets

    _set_stale_preview(first_widget, "old first preview")
    _set_stale_preview(second_widget, "old second preview")
    second_widget.set_error("old error")

    recipe_model.update_operation_args(0, {"edited": True})

    execution_model.set_results(
        [
            StepResult(
                success=True,
                data=TypedOutput(kind=OutputKind.TEXT, value="fresh preview"),
                error=None,
            )
        ]
    )
    execution_model.execution_completed.emit()

    assert first_widget._preview_widget.toPlainText() == "fresh preview"
    assert second_widget._preview_widget.toPlainText() == ""
    assert second_widget._error_visible is False


def test_update_results_clears_all_stale_state_for_empty_results(qtbot):
    _, execution_model, panel = _build_panel(qtbot)

    for index, widget in enumerate(panel._step_widgets):
        _set_stale_preview(widget, f"stale preview {index}")
        widget.set_error(f"old error {index}")

    execution_model.set_results([])
    execution_model.execution_completed.emit()

    for widget in panel._step_widgets:
        assert widget._preview_widget.toPlainText() == ""
        assert widget._error_visible is False
