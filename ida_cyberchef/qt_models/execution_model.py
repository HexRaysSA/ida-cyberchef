"""Qt model for coordinating recipe execution with debouncing.

IMPORTANT: All execution happens in the main thread. PythonMonkey (the
SpiderMonkey-based JavaScript engine used to execute CyberChef operations)
offers no thread-safety guarantees, and the bridge drives promise resolution
through a private asyncio event loop that must only be entered from one
thread.

If future versions migrate to a thread-safe JavaScript engine, background
execution can be implemented using QThread workers.
"""


from PySide6.QtCore import QObject, QTimer, Signal

from ida_cyberchef.core.output_model import typed_output_from_value
from ida_cyberchef.core.recipe_executor import RecipeExecutor, StepResult
from ida_cyberchef.qt_models.input_model import InputModel
from ida_cyberchef.qt_models.recipe_model import RecipeModel


class ExecutionModel(QObject):
    """Coordinates pipeline execution with debouncing.

    All CyberChef operations execute in the main thread due to JS engine
    thread-safety constraints. Debouncing (default 100ms) prevents excessive
    executions when users rapidly change input or recipe.
    """

    execution_completed = Signal()

    def __init__(
        self,
        input_model: InputModel,
        recipe_model: RecipeModel,
        debounce_ms: int = 100,
        parent=None,
    ):
        super().__init__(parent)

        self._input_model = input_model
        self._recipe_model = recipe_model
        self._executor = RecipeExecutor()

        self._results: list[StepResult] = []
        self._preview_results: dict[int, StepResult] = {}

        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(debounce_ms)
        self._debounce_timer.timeout.connect(self._execute_pipeline)

        self._input_model.input_changed.connect(self.schedule_execution)
        self._recipe_model.recipe_changed.connect(self.schedule_execution)

    def schedule_execution(self):
        """Schedule execution after debounce delay."""
        self._debounce_timer.start()

    def _execute_pipeline(self):
        """Execute pipeline (in main thread due to JS engine limitations)."""
        if self._input_model.get_parse_error() is not None:
            self._results = []
            self.execution_completed.emit()
            return

        input_data = self._input_model.get_input_bytes()
        if input_data is None:
            self._results = []
            self.execution_completed.emit()
            return

        recipe = self._recipe_model.get_recipe_steps()
        if not recipe:
            passthrough_result = StepResult(success=True, data=typed_output_from_value(input_data), error=None)
            self._results = [passthrough_result]
            self.execution_completed.emit()
            return

        try:
            results = self._executor.execute_recipe(input_data, recipe)
            self._results = results
        except Exception as e:
            error_result = StepResult(success=False, data=None, error=str(e))
            self._results = [error_result]

        self.execution_completed.emit()

    def get_results(self) -> list[StepResult]:
        """Get results from last execution."""
        return self._results.copy()

    def get_final_result(self) -> StepResult | None:
        """Get final result (last successful step or first error)."""
        return self._results[-1] if self._results else None
