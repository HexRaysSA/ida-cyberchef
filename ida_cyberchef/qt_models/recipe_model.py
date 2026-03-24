"""Qt model for recipe step management."""

from typing import Any, Dict, List

from PySide6.QtCore import QAbstractListModel, Qt, Signal

from ida_cyberchef.core.recipe_models import OperationStep, RecipeDefinition


class RecipeModel(QAbstractListModel):
    """Qt model for managing recipe steps."""

    recipe_changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._steps: List[Dict[str, Any]] = []

    def rowCount(self, parent=None):
        """Return number of steps in recipe."""
        return len(self._steps)

    def data(self, index, role=Qt.DisplayRole):
        """Return data for given index and role."""
        if not index.isValid() or index.row() >= len(self._steps):
            return None

        step = self._steps[index.row()]

        if role == Qt.DisplayRole:
            return step["operation"]
        elif role == Qt.UserRole:
            return step

        return None

    def add_operation(self, operation: str, args: Dict[str, Any], index: int = -1):
        """Add operation to recipe.

        Args:
            operation: Operation name
            args: Operation arguments
            index: Insert position (-1 = append)
        """
        if index < 0:
            index = len(self._steps)

        self.beginInsertRows(self.index(0, 0).parent(), index, index)
        self._steps.insert(index, {"operation": operation, "args": args.copy()})
        self.endInsertRows()

        self.recipe_changed.emit()

    def remove_operation(self, index: int):
        """Remove operation at index."""
        if 0 <= index < len(self._steps):
            self.beginRemoveRows(self.index(0, 0).parent(), index, index)
            self._steps.pop(index)
            self.endRemoveRows()

            self.recipe_changed.emit()

    def update_operation_args(self, index: int, args: Dict[str, Any]):
        """Update arguments for operation at index."""
        if 0 <= index < len(self._steps):
            self._steps[index]["args"] = args.copy()

            model_index = self.index(index, 0)
            self.dataChanged.emit(model_index, model_index)
            self.recipe_changed.emit()

    def get_recipe_steps(self) -> List[Dict[str, Any]]:
        """Get all recipe steps as list of dicts."""
        return [step.copy() for step in self._steps]

    def to_recipe_definition(self) -> RecipeDefinition:
        """Convert to Pydantic model for serialization."""
        steps = [OperationStep(operation=s["operation"], args=s["args"]) for s in self._steps]
        return RecipeDefinition(steps=steps)

    def from_recipe_definition(self, recipe: RecipeDefinition):
        """Load from Pydantic model."""
        self.beginResetModel()
        self._steps = [{"operation": s.operation, "args": s.args} for s in recipe.steps]
        self.endResetModel()

        self.recipe_changed.emit()
