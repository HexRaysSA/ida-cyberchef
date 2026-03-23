"""Main CyberChef widget integrating all panels."""

from PySide6.QtWidgets import QSizePolicy, QVBoxLayout, QWidget

from ida_cyberchef.core.operation_registry import OperationRegistry
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel
from ida_cyberchef.qt_models.recipe_model import RecipeModel
from ida_cyberchef.widgets.input_panel import InputPanel
from ida_cyberchef.widgets.operation_browser_widget import OperationBrowserWidget
from ida_cyberchef.widgets.output_panel import OutputPanel
from ida_cyberchef.widgets.recipe_panel import RecipePanel


class CyberChefWidget(QWidget):
    """Main CyberChef widget with input, recipe, operation browser, and output panels.

    Layout (Vertical layout with fixed input/output/browser, expanding recipe):
    ┌──────────────────────────────────────────────────────────────────────┐
    │ ┌─ Input Panel (minimal fixed height) ────────────────────────────┐  │
    │ │ ◉ Manual Input  ○ From Cursor  ○ From Selection                 │  │
    │ │ Format: ◉ Text (UTF-8)  ○ Hex String  ○ Base64                  │  │
    │ │ ┌──────────────────────────────────────────────────────────────┐│  │
    │ │ │ Enter input data...                                          ││  │
    │ │ └──────────────────────────────────────────────────────────────┘│  │
    │ └─────────────────────────────────────────────────────────────────┘  │
    ├──────────────────────────────────────────────────────────────────────┤
    │ ┌─ Recipe Panel (expands to fill remaining space) ────────────────┐  │
    │ │                         [+ Insert]                              │  │
    │ │ ┌─ To Base64 ────────────────────────────────[Preview ▼] [✕] ─┐ │  │
    │ │ │  Alphabet: │ A-Za-z0-9+/=                                   │ │  │
    │ │ └─────────────────────────────────────────────────────────────┘ │  │
    │ │                         [+ Insert]                              │  │
    │ │ ┌─ XOR ──────────────────────────────────────[Preview ▼] [✕] ─┐ │  │
    │ │ │  Key:    │ secret               │ UTF8                      │ │  │
    │ │ └─────────────────────────────────────────────────────────────┘ │  │
    │ │                    [+ Add Operation]                            │  │
    │ └─────────────────────────────────────────────────────────────────┘  │
    ├──────────────────────────────────────────────────────────────────────┤
    │ ┌─ Operation Browser (fixed height) ──────────────────────────────┐  │
    │ │ Search: │ base64                                                │  │
    │ │ ┌─ Operations ───┬─ Documentation ──────────────────────────┐  │  │
    │ │ │ To Base64      │ **To Base64**                            │  │  │
    │ │ │ From Base64    │ Category: Data format                    │  │  │
    │ │ │ To Hex         │ Converts data to Base64 encoding.        │  │  │
    │ │ └────────────────┴──────────────────────────────────────────┘  │  │
    │ └─────────────────────────────────────────────────────────────────┘  │
    ├──────────────────────────────────────────────────────────────────────┤
    │ ┌─ Output Panel (minimal fixed height) ───────────────────────────┐  │
    │ │ ┌────────────────────────────────────────────────────────────┐  │  │
    │ │ │ 00000000: 48 65 6c 6c 6f 20 77  6f 72 6c 64   Hello world  │  │  │
    │ │ └────────────────────────────────────────────────────────────┘  │  │
    │ │ [Copy to Clipboard] [Save to File]  [Copy to DB] [Set Comment]  │  │
    │ └─────────────────────────────────────────────────────────────────┘  │
    └──────────────────────────────────────────────────────────────────────┘
    """

    def __init__(self, parent=None, show_ida_buttons: bool = False):
        """Initialize CyberChefWidget.

        Args:
            parent: Parent widget
            show_ida_buttons: Whether to show IDA-specific buttons in output panel
        """
        super().__init__(parent)

        self._registry = OperationRegistry()

        self._input_model = InputModel()
        self._recipe_model = RecipeModel()
        self._execution_model = ExecutionModel(self._input_model, self._recipe_model)
        self._show_ida_buttons = show_ida_buttons

        self._setup_ui()

    def _setup_ui(self):
        """Setup main widget UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(0)

        self._input_panel = InputPanel(self._input_model)
        self._input_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        layout.addWidget(self._input_panel)

        self._recipe_panel = RecipePanel(
            self._recipe_model, self._execution_model, self._registry
        )
        self._recipe_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        layout.addWidget(self._recipe_panel)

        self._operation_browser = OperationBrowserWidget(self._registry)
        self._operation_browser.operation_selected.connect(self._on_operation_selected)
        self._operation_browser.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self._operation_browser.setMinimumHeight(200)
        layout.addWidget(self._operation_browser)

        self._output_panel = OutputPanel(
            self._execution_model,
            self._input_model,
            show_ida_buttons=self._show_ida_buttons,
        )
        self._output_panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        layout.addWidget(self._output_panel)

    def get_input_model(self) -> InputModel:
        """Get input model for external data injection.

        Returns: InputModel instance
        """
        return self._input_model

    def get_recipe_model(self) -> RecipeModel:
        """Get recipe model for programmatic recipe manipulation.

        Returns: RecipeModel instance
        """
        return self._recipe_model

    def get_output_panel(self) -> OutputPanel:
        """Get output panel for signal connections.

        Returns: OutputPanel instance
        """
        return self._output_panel

    def get_input_panel(self) -> InputPanel:
        """Get the input panel widget.

        Returns: InputPanel instance
        """
        return self._input_panel

    def set_location_source(self, address: int, length: int) -> None:
        """Set location-backed input state on the input panel.

        Args:
            address: Effective address to read from
            length: Number of bytes to read
        """
        self._input_panel.set_location_source(address, length)

    def _on_operation_selected(self, operation: dict):
        """Handle operation selection from browser widget.

        Args:
            operation: Operation dictionary from registry
        """
        import json
        from typing import Any

        def get_default_arg_value(arg: dict) -> Any:
            """Extract default value from argument definition.

            Args:
                arg: Argument definition from schema

            Returns: Appropriate default value for CyberChef
            """
            arg_type = arg.get("type", "string")
            raw_value = arg.get("value", "")

            try:
                parsed_value = (
                    json.loads(raw_value) if isinstance(raw_value, str) else raw_value
                )
            except (json.JSONDecodeError, ValueError):
                parsed_value = raw_value

            if arg_type in ("option", "editableOption", "editableOptionShort"):
                if isinstance(parsed_value, list) and parsed_value:
                    return parsed_value[0]
                return parsed_value

            elif arg_type == "toggleString":
                toggle_values = arg.get("toggleValues", "[]")
                try:
                    toggle_list = (
                        json.loads(toggle_values)
                        if isinstance(toggle_values, str)
                        else toggle_values
                    )
                except (json.JSONDecodeError, ValueError):
                    toggle_list = []

                if isinstance(toggle_list, list) and toggle_list:
                    return {
                        "string": parsed_value if parsed_value else "",
                        "option": toggle_list[0],
                    }
                return parsed_value

            elif arg_type == "argSelector":
                if isinstance(parsed_value, list) and parsed_value:
                    first_mode = parsed_value[0]
                    if isinstance(first_mode, dict):
                        return first_mode.get("name", "")
                return parsed_value

            return parsed_value

        args = {}
        for arg in operation.get("args", []):
            args[arg["name"]] = get_default_arg_value(arg)

        self._recipe_model.add_operation(operation["name"], args, -1)

    def load_recipe_from_file(self, filename: str):
        """Load recipe from JSON file with validation.

        Args:
            filename: Path to recipe JSON file

        Raises:
            ValueError: If recipe contains operations not in registry
        """
        import json

        from ida_cyberchef.core.recipe_models import RecipeDefinition

        with open(filename) as f:
            data = json.load(f)

        recipe = RecipeDefinition.model_validate(data)

        missing_operations = []
        for step in recipe.steps:
            if not self._registry.find_operation(step.operation):
                missing_operations.append(step.operation)

        if missing_operations:
            raise ValueError(
                f"Recipe contains {len(missing_operations)} unknown operation(s): "
                f"{', '.join(missing_operations[:5])}"
                + (
                    f" and {len(missing_operations) - 5} more"
                    if len(missing_operations) > 5
                    else ""
                )
            )

        self._recipe_model.from_recipe_definition(recipe)

    def save_recipe_to_file(self, filename: str):
        """Save recipe to JSON file.

        Args:
            filename: Path to save recipe JSON
        """
        recipe = self._recipe_model.to_recipe_definition()

        with open(filename, "w") as f:
            f.write(recipe.model_dump_json(indent=2))
