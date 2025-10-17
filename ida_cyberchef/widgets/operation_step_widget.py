"""Widget for displaying and editing a single recipe step."""

import json
from typing import Any, Dict

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTextEdit,
    QWidget,
)

from ida_cyberchef.core.hex_formatter import HexFormatter


class OperationStepWidget(QFrame):
    """Frame widget for single recipe operation step.

    Layout:
    ┌─────────────────────────────────────────────────────────────────────┐
    │ Operation Name  │  Label (80px):  │ Widget spanning cols 2-3       │
    │ (bold, 100px)   │  Another:       │ Input field    │ Dropdown      │
    │      [✕]        │  ☑ Checkbox (no label, self-labeled)             │
    │                 │  Multiline:     │ Text edit spanning 2 columns   │
    ├─────────────────┼──────────────────────────────────────────────────┤
    │ ┌─ Preview (collapsible, 150px max height) ───────────────────────┐ │
    │ │ 00000000: 48 65 6c 6c 6f 20 77 6f  72 6c 64 21  Hello world!    │ │
    │ └─────────────────────────────────────────────────────────────────┘ │
    ├─────────────────────────────────────────────────────────────────────┤
    │ Error: Operation failed (red, bold, hidden by default)              │
    └─────────────────────────────────────────────────────────────────────┘
    """

    args_changed = Signal(int, dict)
    delete_requested = Signal(int)
    preview_toggled = Signal(int, bool)

    def __init__(self, index: int, operation: dict, parent=None):
        super().__init__(parent)

        self._index = index
        self._operation = operation
        self._arg_widgets: Dict[str, QWidget] = {}
        self._preview_visible = False
        self._error_visible = False

        self._hex_formatter = HexFormatter()

        self._setup_ui()

    def _setup_ui(self):
        """Setup widget UI."""
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.setObjectName("OperationStepWidget")
        self.setStyleSheet("""
            QFrame#OperationStepWidget {
                border: 1px solid #505050;
                border-radius: 4px;
                padding: 4px;
            }
        """)

        # Main grid layout with 7 columns
        # 0: Operation name | 1: Labels | 2: Inputs | 3: Secondary | 4: Spacer | 5: Preview | 6: Delete
        main_layout = QGridLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(2)
        main_layout.setHorizontalSpacing(4)
        main_layout.setVerticalSpacing(2)

        # Set column stretch: only column 4 (spacer) expands
        main_layout.setColumnStretch(0, 0)  # Operation name
        main_layout.setColumnStretch(1, 0)  # Arg labels
        main_layout.setColumnStretch(2, 0)  # Input widgets
        main_layout.setColumnStretch(3, 0)  # Secondary widgets
        main_layout.setColumnStretch(4, 1)  # Spacer (expands)
        main_layout.setColumnStretch(5, 0)  # Preview button
        main_layout.setColumnStretch(6, 0)  # Delete button

        # Set column minimum widths
        main_layout.setColumnMinimumWidth(0, 100)  # Operation name
        main_layout.setColumnMinimumWidth(1, 80)  # Arg labels
        main_layout.setColumnMinimumWidth(2, 100)  # Input widgets
        main_layout.setColumnMinimumWidth(5, 18)  # Preview button
        main_layout.setColumnMinimumWidth(6, 18)  # Delete button

        # Operation name label at (0, 0) - no spanning, fixed 100px width
        name_label = QLabel(self._operation["name"])
        name_label.setStyleSheet("font-weight: bold;")
        name_label.setWordWrap(True)
        name_label.setFixedWidth(100)
        name_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        name_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        main_layout.addWidget(name_label, 0, 0)

        # Preview button at (0, 5) - no spanning
        self._preview_button = QPushButton("▼")
        self._preview_button.setToolTip("Preview the data")
        self._preview_button.setFixedSize(16, 16)
        self._preview_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #505050;
                border-radius: 8px;
                color: #666666;
                font-size: 10px;
            }
            QPushButton:hover {
                color: #2196F3;
                border-color: #2196F3;
            }
        """)
        self._preview_button.clicked.connect(self._on_preview_clicked)
        main_layout.addWidget(self._preview_button, 0, 5, Qt.AlignTop)

        # Delete button at (0, 6) - no spanning
        delete_button = QPushButton("✕")
        delete_button.setFixedSize(16, 16)
        delete_button.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #505050;
                border-radius: 8px;
                color: #666666;
                font-size: 12px;
            }
            QPushButton:hover {
                color: #2196F3;
                border-color: #2196F3;
            }
        """)
        delete_button.clicked.connect(lambda: self.delete_requested.emit(self._index))
        main_layout.addWidget(delete_button, 0, 6, Qt.AlignTop)

        # Args grid will be populated in columns 1-3
        self._args_grid = main_layout
        self._args_grid.setColumnMinimumWidth(1, 80)

        self._populate_args_grid()

        # Calculate next row for preview/error widgets
        arg_count = len(self._operation.get("args", []))
        next_row = arg_count if arg_count > 0 else 1

        # Preview widget (spans all 7 columns)
        self._preview_widget = QTextEdit()
        self._preview_widget.setReadOnly(True)
        self._preview_widget.setMaximumHeight(150)
        self._preview_widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._preview_widget.setVisible(False)
        self._preview_widget.setStyleSheet(
            "font-family: 'Courier New', Courier, monospace; margin-top: 8px;"
        )
        main_layout.addWidget(self._preview_widget, next_row, 0, 1, 7)

        # Error label (spans all 7 columns)
        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: red; font-weight: bold;")
        self._error_label.setVisible(False)
        self._error_label.setWordWrap(True)
        self._error_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        main_layout.addWidget(self._error_label, next_row + 1, 0, 1, 7)

    def _populate_args_grid(self):
        """Populate grid with argument widgets and labels."""
        row = 0  # Start at row 0 (same row as operation name)

        for arg in self._operation.get("args", []):
            arg_type = arg.get("type", "string")
            arg_name = arg["name"]

            widget = self._create_arg_widget(arg)
            self._arg_widgets[arg_name] = widget

            # Boolean checkbox is self-labeled, no separate label needed
            if arg_type == "boolean":
                self._args_grid.addWidget(widget, row, 2, 1, 2)

            # ToggleString needs 3 columns: label | input | format dropdown
            elif arg_type == "toggleString":
                label = QLabel(arg_name + ":")
                label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                label.setStyleSheet("color: #666;")
                label.setWordWrap(True)
                label.setFixedWidth(80)
                self._args_grid.addWidget(label, row, 1)

                # Widget is container with value_input and format_combo
                # We need to extract and place them separately
                value_input = widget.property("value_input")
                format_combo = widget.property("format_combo")

                if value_input:
                    self._args_grid.addWidget(value_input, row, 2)
                if format_combo:
                    self._args_grid.addWidget(format_combo, row, 3)

            # Text/multiline: label | text edit spanning 2 columns
            elif arg_type in ("text", "binaryString"):
                label = QLabel(arg_name + ":")
                label.setAlignment(Qt.AlignRight | Qt.AlignTop)
                label.setStyleSheet("color: #666;")
                label.setWordWrap(True)
                label.setFixedWidth(80)
                self._args_grid.addWidget(label, row, 1)
                self._args_grid.addWidget(widget, row, 2, 1, 2)

            # Label type: no label, just display widget
            elif arg_type == "label":
                self._args_grid.addWidget(widget, row, 2, 1, 2)

            # All other types: label | widget spanning columns 2-3
            else:
                label = QLabel(arg_name + ":")
                label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                label.setStyleSheet("color: #666;")
                label.setWordWrap(True)
                label.setFixedWidth(80)
                self._args_grid.addWidget(label, row, 1)
                self._args_grid.addWidget(widget, row, 2, 1, 2)

            row += 1

    def _parse_json_value(self, value: Any) -> Any:
        """Parse JSON-encoded value if it's a string.

        Args:
            value: Value from schema (may be JSON-encoded string)

        Returns: Parsed value or original if not JSON
        """
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, ValueError):
                return value
        return value

    def _create_arg_widget(self, arg: dict) -> QWidget:
        """Create appropriate widget for argument type.

        Args:
            arg: Argument definition dict

        Returns: Widget for editing argument value
        """
        arg_type = arg.get("type", "string")
        raw_value = arg.get("value", "")
        parsed_value = self._parse_json_value(raw_value)

        # Boolean checkbox
        if arg_type == "boolean":
            widget = QCheckBox(arg["name"])
            widget.setChecked(parsed_value if isinstance(parsed_value, bool) else False)
            # Connect signal AFTER setting initial value
            widget.stateChanged.connect(self._on_arg_changed)
            return widget

        # Number spinner
        elif arg_type == "number":
            widget = QSpinBox()
            widget.setValue(
                int(parsed_value) if isinstance(parsed_value, (int, float)) else 0
            )
            widget.setRange(-999999, 999999)
            widget.setMaximumWidth(100)
            # Connect signal AFTER setting initial value
            widget.valueChanged.connect(self._on_arg_changed)
            return widget

        # Option dropdown (JSON array of choices)
        elif arg_type == "option":
            widget = QComboBox()
            if isinstance(parsed_value, list):
                # Schema default: value is array of choices
                widget.addItems(parsed_value)
                widget.setCurrentIndex(0)

                # If there's a saved selection, use it
                saved = arg.get("saved_value")
                if saved and saved in parsed_value:
                    widget.setCurrentText(saved)
            elif isinstance(parsed_value, str):
                # Fallback: value is a single string (shouldn't happen with new recipe_panel)
                widget.addItem(parsed_value)

            widget.setMaximumWidth(200)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.currentTextChanged.connect(self._on_arg_changed)
            return widget

        # Editable option dropdown
        elif arg_type in ("editableOption", "editableOptionShort"):
            widget = QComboBox()
            widget.setEditable(True)
            if isinstance(parsed_value, list):
                widget.addItems(parsed_value)
                widget.setCurrentIndex(0)

                saved = arg.get("saved_value")
                if saved:
                    # For editable, saved might not be in list
                    widget.setCurrentText(saved)
            elif isinstance(parsed_value, str):
                widget.addItem(parsed_value)

            widget.setMaximumWidth(200)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.currentTextChanged.connect(self._on_arg_changed)
            return widget

        # Toggle string (value input + format dropdown)
        elif arg_type == "toggleString":
            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(0, 0, 0, 0)

            # Check for saved_value first (takes precedence when reloading)
            saved_value = arg.get("saved_value")
            value_to_use = saved_value if saved_value is not None else parsed_value

            # Extract string and option from dict or use raw value
            if isinstance(value_to_use, dict):
                string_value = value_to_use.get("string", "")
                selected_option = value_to_use.get("option", "")
            else:
                string_value = str(value_to_use) if value_to_use else ""
                selected_option = ""

            # Value input
            value_input = QLineEdit()
            value_input.setPlaceholderText(arg["name"])
            value_input.setText(string_value)
            value_input.setMaximumWidth(200)
            value_input.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            value_input.textChanged.connect(self._on_arg_changed)
            layout.addWidget(value_input)

            # Format dropdown
            toggle_values = self._parse_json_value(arg.get("toggleValues", "[]"))
            format_combo = None
            if isinstance(toggle_values, list) and toggle_values:
                format_combo = QComboBox()
                format_combo.addItems(toggle_values)
                format_combo.setMaximumWidth(100)
                layout.addWidget(format_combo)

                # Set saved option or default to first
                if selected_option and selected_option in toggle_values:
                    format_combo.setCurrentText(selected_option)
                else:
                    format_combo.setCurrentIndex(0)

                # Connect signal AFTER setting initial selection
                format_combo.currentTextChanged.connect(self._on_arg_changed)

            # Store both widgets in container's properties
            container.setProperty("value_input", value_input)
            container.setProperty("format_combo", format_combo)
            return container

        # Arg selector (mode dropdown with conditional args)
        elif arg_type == "argSelector":
            widget = QComboBox()
            if isinstance(parsed_value, list):
                mode_names = [
                    mode.get("name", f"Mode {i}")
                    if isinstance(mode, dict)
                    else str(mode)
                    for i, mode in enumerate(parsed_value)
                ]
                widget.addItems(mode_names)
                widget.setCurrentIndex(0)
            widget.setMaximumWidth(200)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.currentTextChanged.connect(self._on_arg_changed)
            return widget

        # Label (display-only)
        elif arg_type == "label":
            widget = QLabel(str(parsed_value))
            return widget

        # Text/multiline string
        elif arg_type in ("text", "binaryString"):
            widget = QTextEdit()
            widget.setPlainText(str(parsed_value) if parsed_value else "")
            widget.setMaximumHeight(80)
            widget.setMaximumWidth(300)
            widget.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.textChanged.connect(self._on_arg_changed)
            return widget

        # Enum (legacy, kept for compatibility)
        elif arg_type == "enum":
            widget = QComboBox()
            widget.addItems(arg.get("options", []))
            current = str(parsed_value) if parsed_value else ""
            if current in arg.get("options", []):
                widget.setCurrentText(current)
            widget.setMaximumWidth(200)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.currentTextChanged.connect(self._on_arg_changed)
            return widget

        # Default: string/shortString/binaryShortString
        else:
            widget = QLineEdit()
            widget.setPlaceholderText(arg["name"])
            widget.setText(str(parsed_value) if parsed_value else "")
            widget.setMaximumWidth(200)
            widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            # Connect signal AFTER setting initial value
            widget.textChanged.connect(self._on_arg_changed)
            return widget

    def _on_arg_changed(self):
        """Handle argument value changes."""
        args = self.get_current_args()
        self.args_changed.emit(self._index, args)

    def _on_preview_clicked(self):
        """Handle preview button click."""
        self._preview_visible = not self._preview_visible
        self._preview_widget.setVisible(self._preview_visible)
        self.preview_toggled.emit(self._index, self._preview_visible)

    def get_current_args(self) -> Dict[str, Any]:
        """Get current argument values.

        Returns: Dict of argument name -> value
        """
        args = {}

        for arg in self._operation.get("args", []):
            arg_name = arg["name"]
            arg_type = arg.get("type", "string")
            widget = self._arg_widgets[arg_name]

            # Boolean checkbox
            if isinstance(widget, QCheckBox):
                args[arg_name] = widget.isChecked()

            # Number spinner
            elif isinstance(widget, QSpinBox):
                args[arg_name] = widget.value()

            # Combobox (option, editableOption, argSelector, enum)
            elif isinstance(widget, QComboBox):
                args[arg_name] = widget.currentText()

            # Text edit (text, binaryString)
            elif isinstance(widget, QTextEdit):
                args[arg_name] = widget.toPlainText()

            # Label (display-only, no value)
            elif isinstance(widget, QLabel):
                args[arg_name] = widget.text()

            # Compound toggleString widget
            elif arg_type == "toggleString":
                value_input = widget.property("value_input")
                format_combo = widget.property("format_combo")
                if value_input:
                    value = value_input.text()
                    # If format combo exists, CyberChef expects dict with value and option
                    if format_combo:
                        args[arg_name] = {
                            "string": value,
                            "option": format_combo.currentText(),
                        }
                    else:
                        args[arg_name] = value

            # Line edit (default for string types)
            elif isinstance(widget, QLineEdit):
                args[arg_name] = widget.text()

            # Fallback
            else:
                args[arg_name] = ""

        return args

    def set_preview_data(self, data: bytes):
        """Set preview data to display.

        Args:
            data: Bytes to display as hex dump
        """
        hex_dump = self._hex_formatter.format_hex_dump(data)
        self._preview_widget.setPlainText(hex_dump)

    def set_error(self, error: str):
        """Set error state and message.

        Args:
            error: Error message
        """
        self._error_visible = True
        self._error_label.setText(f"Error: {error}")
        self._error_label.setVisible(True)

        if not self._preview_visible:
            self._on_preview_clicked()

        self.setStyleSheet("""
            QFrame#OperationStepWidget {
                border: 1px solid #ff0000;
                border-radius: 4px;
                padding: 4px;
            }
        """)

    def clear_error(self):
        """Clear error state."""
        self._error_visible = False
        self._error_label.setVisible(False)
        self.setStyleSheet("""
            QFrame#OperationStepWidget {
                border: 1px solid #505050;
                border-radius: 4px;
                padding: 4px;
            }
        """)
