"""Recipe panel widget for managing recipe steps."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.recipe_model import RecipeModel
from ida_cyberchef.qt_models.schema_adapter import (
    get_operation_default_args,
    normalise_operation_view_model,
)
from ida_cyberchef.widgets.insert_indicator_widget import InsertIndicatorWidget
from ida_cyberchef.widgets.operation_search_dialog import OperationSearchDialog
from ida_cyberchef.widgets.operation_step_widget import OperationStepWidget


class RecipePanel(QWidget):
    """Panel for recipe step management.

    Layout:
    ┌─────────────────────────────────────────────────────────────────────┐
    │ ┌─ Scroll Area ───────────────────────────────────────────────────┐ │
    │ │                        ⊕────────────────                        │ │
    │ │ ┌─ OperationStepWidget ──────────────────────────────────────┐  │ │
    │ │ │ To Base64                           [Preview ▼] [✕]       ││  │ │
    │ │ │  Alphabet: │ A-Za-z0-9+/=                                 ││  │ │
    │ │ └────────────────────────────────────────────────────────────┘  │ │
    │ │                        ⊕────────────────                        │ │
    │ │ ┌─ OperationStepWidget ──────────────────────────────────────┐  │ │
    │ │ │ XOR                                 [Preview ▼] [✕]       ││  │ │
    │ │ │  Key:      │ secret               │ UTF8                  ││  │ │
    │ │ │  Scheme:   │ Standard                                     ││  │ │
    │ │ └────────────────────────────────────────────────────────────┘  │ │
    │ │                        ⊕────────────────                        │ │
    │ │ (more steps...)                                                 │ │
    │ └─────────────────────────────────────────────────────────────────┘ │
    └─────────────────────────────────────────────────────────────────────┘

    Operations are added via the persistent Operation Browser Widget at bottom.
    """

    def __init__(
        self,
        recipe_model: RecipeModel,
        execution_model: ExecutionModel,
        registry: OperationRegistry,
        parent=None,
    ):
        super().__init__(parent)

        self._recipe_model = recipe_model
        self._execution_model = execution_model
        self._registry = registry

        self._step_widgets: list[OperationStepWidget] = []

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setContentsMargins(0, 0, 0, 0)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        self._steps_container = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_container)
        self._steps_layout.setContentsMargins(0, 0, 0, 0)
        self._steps_layout.setSpacing(4)

        scroll.setWidget(self._steps_container)
        layout.addWidget(scroll)

    def _connect_signals(self):
        """Connect signals and slots."""
        self._recipe_model.rowsInserted.connect(self._refresh_display)
        self._recipe_model.rowsRemoved.connect(self._refresh_display)
        self._recipe_model.modelReset.connect(self._refresh_display)

        self._execution_model.execution_completed.connect(self._update_results)

    def _refresh_display(self):
        """Refresh the display of recipe steps."""
        while self._steps_layout.count():
            item = self._steps_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._step_widgets.clear()

        steps = self._recipe_model.get_recipe_steps()

        for i, step in enumerate(steps):
            insert_indicator = InsertIndicatorWidget()
            insert_indicator.clicked.connect(lambda idx=i: self._show_operation_dialog(idx))
            self._steps_layout.addWidget(insert_indicator)

            op_info = self._registry.find_operation(step["operation"])
            if op_info:
                widget = OperationStepWidget(
                    i,
                    normalise_operation_view_model(op_info, step["args"]),
                )
                widget.args_changed.connect(self._on_args_changed)
                widget.delete_requested.connect(self._on_delete_requested)
                widget.preview_toggled.connect(self._on_preview_toggled)

                self._steps_layout.addWidget(widget)
                self._step_widgets.append(widget)

        self._steps_layout.addStretch()

    def _show_operation_dialog(self, insert_index: int):
        """Show operation selection dialog.

        Args:
            insert_index: Index to insert at (-1 = append)
        """
        dialog = OperationSearchDialog(self._registry, self)
        if dialog.exec():
            op = dialog.get_selected_operation()
            if op:
                args = get_operation_default_args(op)
                self._recipe_model.add_operation(op["name"], args, insert_index)

    def _on_args_changed(self, index: int, args: dict):
        """Handle argument changes."""
        self._recipe_model.update_operation_args(index, args)

    def _on_delete_requested(self, index: int):
        """Handle delete request."""
        self._recipe_model.remove_operation(index)

    def _on_preview_toggled(self, index: int, expanded: bool):
        """Handle preview toggle."""
        if expanded:
            self._execution_model.schedule_execution()

    def _update_results(self):
        """Update step widgets with execution results."""
        results = self._execution_model.get_results()

        for widget in self._step_widgets:
            widget.clear_error()
            widget.clear_preview()

        for i, widget in enumerate(self._step_widgets):
            if i < len(results):
                result = results[i]

                if result.success and result.data is not None:
                    widget.set_preview_data(result.data)
                elif not result.success and result.error is not None:
                    widget.set_error(result.error)
