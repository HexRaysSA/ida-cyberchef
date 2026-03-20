"""Output panel widget for displaying results."""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ida_cyberchef.core.hex_formatter import HexFormatter
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel, InputSource

logger = logging.getLogger(__name__)


class OutputPanel(QWidget):
    """Panel for displaying output and actions.

    Layout:
    ┌──────────────────────────────────────────────────────────────────────┐
    │ ┌─ Output Display (monospace, read-only) ──────────────────────────┐ │
    │ │ 00000000: 48 65 6c 6c 6f 20 77 6f  72 6c 64 21  Hello world!     │ │
    │ │ 00000010: 0a                                     .               │ │
    │ │                                                                  │ │
    │ │ Output will appear here...                                       │ │
    │ └──────────────────────────────────────────────────────────────────┘ │
    ├──────────────────────────────────────────────────────────────────────┤
    │ [Copy to Clipboard] [Save to File]   [Copy to DB] [Set Comment]      │
    │                                       (enabled)    (disabled)        │
    └──────────────────────────────────────────────────────────────────────┘

    Note: Copy to DB button is enabled when input source is FROM_SELECTION or FROM_LOCATION.

    Signals:
        copy_to_db_requested: Emitted when user requests to copy output to IDB.
            Args: (address: int, data: bytes)
        set_comment_requested: Emitted when user requests to set a comment.
            Args: (text: str)
    """

    copy_to_db_requested = Signal(object, object)
    set_comment_requested = Signal(str)

    def __init__(
        self,
        execution_model: ExecutionModel,
        input_model: InputModel,
        parent=None,
        show_ida_buttons: bool = False,
    ):
        """Initialize OutputPanel.

        Args:
            execution_model: Model for recipe execution
            input_model: Model for input data
            parent: Parent widget
            show_ida_buttons: Whether to show IDA-specific buttons (Copy to DB, Set Comment)
        """
        super().__init__(parent)

        self._execution_model = execution_model
        self._input_model = input_model
        self._hex_formatter = HexFormatter()
        self._current_output: bytes | str = b""
        self._show_ida_buttons = show_ida_buttons

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup panel UI."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(4)

        self._output_display = QTextEdit()
        self._output_display.setReadOnly(True)
        self._output_display.setStyleSheet(
            "font-family: 'Courier New', Courier, monospace;"
        )
        self._output_display.setPlaceholderText("Output will appear here...")
        self._output_display.setMinimumHeight(100)
        self._output_display.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._output_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self._output_display)

        # Output format combo box (overlay in bottom-right)
        self._output_format_combo = QComboBox(self)
        self._output_format_combo.addItems(
            [
                "Hex Dump",
                "Text",
                "Hex String (Unspaced)",
                "Hex String (Spaced)",
                "String Literal",
                "C Array (Hex)",
                "C Array (Decimal)",
                "C Variable",
            ]
        )
        self._output_format_combo.setMinimumWidth(150)
        self._output_format_combo.currentTextChanged.connect(self._on_format_changed)
        self._output_format_combo.raise_()

        button_container = QWidget()
        button_container.setFixedWidth(45)
        button_container.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        button_layout = QVBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(4)

        self._copy_button = QPushButton("📋")
        self._copy_button.setToolTip("Copy to clipboard")
        self._copy_button.clicked.connect(self._on_copy_clicked)
        button_layout.addWidget(self._copy_button)

        self._save_button = QPushButton("💾")
        self._save_button.setToolTip("Save to file")
        self._save_button.clicked.connect(self._on_save_clicked)
        button_layout.addWidget(self._save_button)

        if self._show_ida_buttons:
            self._copy_db_button = QPushButton("➡️")
            self._copy_db_button.setToolTip(
                "Copy to IDB (only available when input source is 'From Selection' or 'From Location')"
            )
            self._copy_db_button.setEnabled(False)
            self._copy_db_button.clicked.connect(self._on_copy_db_clicked)
            button_layout.addWidget(self._copy_db_button)

            self._set_comment_button = QPushButton("💬")
            self._set_comment_button.setToolTip("Set comment at cursor")
            self._set_comment_button.setEnabled(False)
            self._set_comment_button.clicked.connect(self._on_set_comment_clicked)
            button_layout.addWidget(self._set_comment_button)
        else:
            self._copy_db_button = None
            self._set_comment_button = None

        button_layout.addStretch()

        main_layout.addWidget(button_container)

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Reposition overlay combo box on resize."""
        super().resizeEvent(event)

        # Position combo box in bottom-right of output display
        # Only position if there's enough horizontal space to avoid overlap
        if self._output_display.width() > 200:
            combo_width = self._output_format_combo.width()
            combo_height = self._output_format_combo.height()

            # Get output display geometry
            display_rect = self._output_display.geometry()

            x = display_rect.right() - combo_width - 10
            y = display_rect.bottom() - combo_height - 6

            self._output_format_combo.move(x, y)

    def _connect_signals(self):
        """Connect signals and slots."""
        self._execution_model.execution_completed.connect(self._update_output)
        self._input_model.source_changed.connect(self._on_input_source_changed)
        self._on_input_source_changed(self._input_model.get_input_source())

    def _update_output(self):
        """Update output display with execution results."""
        result = self._execution_model.get_final_result()

        if result and result.success and result.data is not None:
            self._current_output = result.data
            self._auto_select_format(result.data)
            self._render_output(result.data)
            if self._set_comment_button is not None:
                self._set_comment_button.setEnabled(True)
        elif result and not result.success:
            self._current_output = b""
            self._output_display.setPlainText(f"Error: {result.error}")
            if self._set_comment_button is not None:
                self._set_comment_button.setEnabled(False)
        else:
            self._current_output = b""
            self._output_display.clear()
            if self._set_comment_button is not None:
                self._set_comment_button.setEnabled(False)

    def _render_output(self, data: bytes | str):
        """Render output data using selected format.

        Args:
            data: Bytes or string to render
        """
        format_name = self._output_format_combo.currentText()

        if format_name == "Text":
            if isinstance(data, str):
                formatted = data
            else:
                try:
                    formatted = data.decode("utf-8")
                except UnicodeDecodeError:
                    formatted = data.decode("utf-8", errors="replace")
        else:
            if isinstance(data, str):
                data_bytes = data.encode("utf-8")
            else:
                data_bytes = data

            if format_name == "Hex Dump":
                formatted = self._hex_formatter.format_hex_dump(data_bytes)
            elif format_name == "Hex String (Unspaced)":
                formatted = self._hex_formatter.format_hex_string_unspaced(data_bytes)
            elif format_name == "Hex String (Spaced)":
                formatted = self._hex_formatter.format_hex_string_spaced(data_bytes)
            elif format_name == "String Literal":
                formatted = self._hex_formatter.format_string_literal(data_bytes)
            elif format_name == "C Array (Hex)":
                formatted = self._hex_formatter.format_c_uchar_array_hex(data_bytes)
            elif format_name == "C Array (Decimal)":
                formatted = self._hex_formatter.format_c_uchar_array_decimal(data_bytes)
            elif format_name == "C Variable":
                formatted = self._hex_formatter.format_c_initialized_variable(
                    data_bytes
                )
            else:
                formatted = self._hex_formatter.format_hex_dump(data_bytes)

        self._output_display.setPlainText(formatted)

    def _on_format_changed(self):
        """Handle output format change."""
        # Re-render current output with new format
        if self._current_output:
            self._render_output(self._current_output)

    def _auto_select_format(self, data: bytes | str):
        """Auto-select output format based on data type.

        Args:
            data: Output data (str for text, bytes for binary)
        """
        if isinstance(data, str):
            self._output_format_combo.setCurrentText("Text")
        else:
            self._output_format_combo.setCurrentText("Hex Dump")

    def _on_copy_clicked(self):
        """Handle copy to clipboard."""
        if self._current_output:
            clipboard = QApplication.clipboard()
            clipboard.setText(self._output_display.toPlainText())

            QMessageBox.information(
                self,
                "Copied",
                "Copied formatted output to clipboard",
            )

    def _on_save_clicked(self):
        """Handle save to file."""
        if not self._current_output:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", "", "All Files (*)"
        )

        if filename:
            try:
                data_to_write = (
                    self._current_output.encode("utf-8")
                    if isinstance(self._current_output, str)
                    else self._current_output
                )

                with open(filename, "wb") as f:
                    f.write(data_to_write)

                QMessageBox.information(
                    self,
                    "Saved",
                    f"Saved {len(data_to_write)} bytes to {filename}",
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")

    def _on_input_source_changed(self, source: InputSource):
        """Handle input source change to enable/disable Copy to IDB button.

        Args:
            source: The new input source
        """
        if self._copy_db_button is None:
            return

        if source in (InputSource.FROM_SELECTION, InputSource.FROM_LOCATION):
            self._copy_db_button.setEnabled(True)
            self._copy_db_button.setToolTip("Copy to IDB")
        else:
            self._copy_db_button.setEnabled(False)
            self._copy_db_button.setToolTip(
                "Copy to IDB (only available when input source is 'From Selection' or 'From Location')"
            )

    def _on_copy_db_clicked(self):
        """Handle copy to IDB action.

        Emits copy_to_db_requested signal with address and data.
        Only works when input source is FROM_SELECTION or FROM_LOCATION.
        """
        if not self._current_output:
            logger.warning("No output available to copy to IDB")
            return

        if isinstance(self._current_output, str):
            QMessageBox.warning(
                self,
                "Invalid Output Type",
                "Cannot copy string output to IDB. Only binary data can be patched.",
            )
            return

        address = self._input_model.get_external_address()
        if address is None:
            logger.warning(
                "Cannot determine address to patch (no selection address stored)"
            )
            return

        self.copy_to_db_requested.emit(address, self._current_output)

    def _on_set_comment_clicked(self):
        """Handle set comment at cursor action.

        Emits set_comment_requested signal with comment text.
        """
        comment_text = self._output_display.toPlainText()
        self.set_comment_requested.emit(comment_text)
