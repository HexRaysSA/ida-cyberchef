"""Output panel widget for displaying results."""

import io
import json
import logging
import zipfile

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
from ida_cyberchef.core.output_model import OutputKind, TypedOutput
from ida_cyberchef.qt_models.execution_model import ExecutionModel
from ida_cyberchef.qt_models.input_model import InputModel, InputSource

logger = logging.getLogger(__name__)

_BYTES_FORMATS = [
    "Hex Dump",
    "Text",
    "Hex String (Unspaced)",
    "Hex String (Spaced)",
    "String Literal",
    "C Array (Hex)",
    "C Array (Decimal)",
    "C Variable",
]

_FORMATS_FOR_KIND: dict[OutputKind, list[str]] = {
    OutputKind.BYTES: _BYTES_FORMATS,
    OutputKind.TEXT: ["Text"],
    OutputKind.NUMBER: ["Text"],
    OutputKind.JSON: ["Pretty JSON", "Compact JSON"],
    OutputKind.FILE: ["Hex Dump", "Text", "File Info"],
    OutputKind.FILE_LIST: ["File List Summary"],
    OutputKind.ERROR: [],
}

_DEFAULT_FORMAT_FOR_KIND: dict[OutputKind, str] = {
    OutputKind.BYTES: "Hex Dump",
    OutputKind.TEXT: "Text",
    OutputKind.NUMBER: "Text",
    OutputKind.JSON: "Pretty JSON",
    OutputKind.FILE: "Hex Dump",
    OutputKind.FILE_LIST: "File List Summary",
    OutputKind.ERROR: "",
}


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

    Note: Copy to DB button is enabled when input source is FROM_SELECTION or FROM_LOCATION
    and the output kind is BYTES.

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
        self._current_output: TypedOutput | None = None
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

        self._output_format_combo = QComboBox(self)
        self._output_format_combo.addItems(_BYTES_FORMATS)
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
        self._copy_button.setEnabled(False)
        self._copy_button.clicked.connect(self._on_copy_clicked)
        button_layout.addWidget(self._copy_button)

        self._save_button = QPushButton("💾")
        self._save_button.setToolTip("Save to file")
        self._save_button.setEnabled(False)
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

        if self._output_display.width() > 200:
            combo_width = self._output_format_combo.width()
            combo_height = self._output_format_combo.height()

            display_rect = self._output_display.geometry()

            x = display_rect.right() - combo_width - 10
            y = display_rect.bottom() - combo_height - 6

            self._output_format_combo.move(x, y)

    def _connect_signals(self):
        """Connect signals and slots."""
        self._execution_model.execution_completed.connect(self._update_output)
        self._input_model.source_changed.connect(self._on_input_source_changed)
        self._update_button_states()

    def _formats_for_kind(self, kind: OutputKind) -> list[str]:
        """Return the list of display format names available for an output kind."""
        return _FORMATS_FOR_KIND.get(kind, ["Text"])

    def _repopulate_format_combo(self, kind: OutputKind, preserve_selection: bool = True) -> None:
        """Repopulate the format combo box for a new output kind.

        Args:
            kind: The output kind whose formats should be shown.
            preserve_selection: If True and the kind hasn't changed, keep the
                current selection if it is still valid.
        """
        current_text = self._output_format_combo.currentText()
        formats = self._formats_for_kind(kind)

        self._output_format_combo.blockSignals(True)
        self._output_format_combo.clear()
        self._output_format_combo.addItems(formats)

        if preserve_selection and current_text in formats:
            self._output_format_combo.setCurrentText(current_text)
        elif formats:
            default = _DEFAULT_FORMAT_FOR_KIND.get(kind, formats[0])
            self._output_format_combo.setCurrentText(default)

        self._output_format_combo.blockSignals(False)
        self._output_format_combo.setVisible(bool(formats))

    def _update_output(self):
        """Update output display with execution results."""
        result = self._execution_model.get_final_result()

        prev_kind = self._current_output.kind if self._current_output is not None else None

        if result and result.success and result.data is not None:
            self._current_output = result.data
            same_kind = prev_kind == result.data.kind
            self._repopulate_format_combo(result.data.kind, preserve_selection=same_kind)
            self._render_output(result.data)
        elif result and not result.success:
            self._current_output = None
            self._output_display.setPlainText(f"Error: {result.error}")
        else:
            self._current_output = None
            self._output_display.clear()

        self._update_button_states()

    def _render_output(self, output: TypedOutput) -> None:
        """Render a TypedOutput using the currently selected format."""
        format_name = self._output_format_combo.currentText()
        formatted = self._format_output(output, format_name)
        self._output_display.setPlainText(formatted)

    def _format_output(self, output: TypedOutput, format_name: str) -> str:
        """Return a string representation of output for the given format name."""
        kind = output.kind
        value = output.value

        if kind == OutputKind.TEXT:
            return str(value)

        if kind == OutputKind.NUMBER:
            return str(value)

        if kind == OutputKind.JSON:
            if format_name == "Compact JSON":
                return json.dumps(value, separators=(",", ":"))
            return json.dumps(value, indent=2)

        if kind == OutputKind.FILE:
            if format_name == "Text":
                try:
                    return value["data"].decode("utf-8")
                except (UnicodeDecodeError, AttributeError):
                    return value["data"].decode("utf-8", errors="replace")
            if format_name == "File Info":
                data = value.get("data", b"")
                return (
                    f"Name: {value.get('name', '')}\n"
                    f"Type: {value.get('type', '')}\n"
                    f"Size: {len(data)} bytes"
                )
            return self._hex_formatter.format_hex_dump(value.get("data", b""))

        if kind == OutputKind.FILE_LIST:
            lines = []
            for item in value:
                data = item.get("data", b"")
                lines.append(
                    f"{item.get('name', '(unnamed)')}\t"
                    f"{item.get('type', '')}\t"
                    f"{len(data)} bytes"
                )
            return "\n".join(lines)

        if kind == OutputKind.BYTES:
            data_bytes: bytes = value
            if format_name == "Text":
                try:
                    return data_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    return data_bytes.decode("utf-8", errors="replace")
            if format_name == "Hex String (Unspaced)":
                return self._hex_formatter.format_hex_string_unspaced(data_bytes)
            if format_name == "Hex String (Spaced)":
                return self._hex_formatter.format_hex_string_spaced(data_bytes)
            if format_name == "String Literal":
                return self._hex_formatter.format_string_literal(data_bytes)
            if format_name == "C Array (Hex)":
                return self._hex_formatter.format_c_uchar_array_hex(data_bytes)
            if format_name == "C Array (Decimal)":
                return self._hex_formatter.format_c_uchar_array_decimal(data_bytes)
            if format_name == "C Variable":
                return self._hex_formatter.format_c_initialized_variable(data_bytes)
            return self._hex_formatter.format_hex_dump(data_bytes)

        return str(value)

    def _on_format_changed(self):
        """Handle output format change."""
        if self._current_output is not None:
            self._render_output(self._current_output)

    def _on_copy_clicked(self):
        """Handle copy to clipboard."""
        if self._current_output is not None:
            clipboard = QApplication.clipboard()
            clipboard.setText(self._output_display.toPlainText())
            logger.info("Copied formatted output to clipboard")

    def _on_save_clicked(self):
        """Handle save to file."""
        if self._current_output is None:
            return

        kind = self._current_output.kind
        value = self._current_output.value

        if kind == OutputKind.FILE_LIST:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Output", "output.zip", "Zip Archives (*.zip);;All Files (*)"
            )
            if not filename:
                return
            try:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for item in value:
                        zf.writestr(item.get("name", "file"), item.get("data", b""))
                data_to_write = buf.getvalue()
                with open(filename, "wb") as f:
                    f.write(data_to_write)
                QMessageBox.information(self, "Saved", f"Saved {len(value)} files to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")
            return

        if kind == OutputKind.FILE:
            default_name = value.get("name", "output.bin")
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save Output", default_name, "All Files (*)"
            )
            if not filename:
                return
            try:
                with open(filename, "wb") as f:
                    f.write(value.get("data", b""))
                QMessageBox.information(self, "Saved", f"Saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {e}")
            return

        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", "", "All Files (*)"
        )
        if not filename:
            return

        try:
            if kind == OutputKind.BYTES:
                data_to_write = value
            else:
                data_to_write = self._output_display.toPlainText().encode("utf-8")

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
        """Handle input source change."""
        self._update_button_states()

    def _update_button_states(self):
        """Update enabled state and tooltips for all action buttons."""
        has_output = self._current_output is not None

        self._copy_button.setEnabled(has_output)
        self._save_button.setEnabled(has_output)

        if self._set_comment_button is not None:
            self._set_comment_button.setEnabled(has_output)

        if self._copy_db_button is not None:
            source = self._input_model.get_input_source()
            has_address = source in (InputSource.FROM_SELECTION, InputSource.FROM_LOCATION)
            has_bytes_output = (
                has_output
                and self._current_output is not None
                and self._current_output.kind == OutputKind.BYTES
                and len(self._current_output.value) > 0
            )

            if has_address and has_bytes_output:
                self._copy_db_button.setEnabled(True)
                self._copy_db_button.setToolTip("Patch output bytes into IDB")
            elif not has_address:
                self._copy_db_button.setEnabled(False)
                self._copy_db_button.setToolTip(
                    "Copy to IDB requires input source 'From Selection' or 'From Location'"
                )
            else:
                self._copy_db_button.setEnabled(False)
                self._copy_db_button.setToolTip(
                    "Copy to IDB requires recipe output to be bytes, not text. "
                    "Add an operation like 'To Hex' → 'From Hex' or adjust your recipe."
                )

    def _on_copy_db_clicked(self):
        """Handle copy to IDB action.

        Emits copy_to_db_requested signal with address and data.
        Only works when input source is FROM_SELECTION or FROM_LOCATION.
        """
        logger.debug(
            "copy to IDB clicked: output kind=%s, source=%s",
            self._current_output.kind.name if self._current_output else "None",
            self._input_model.get_input_source().name,
        )

        if self._current_output is None:
            logger.warning("No output available to copy to IDB")
            return

        if self._current_output.kind != OutputKind.BYTES:
            logger.warning(
                "Recipe output kind is %s, not BYTES — cannot patch IDB",
                self._current_output.kind.name,
            )
            return

        address = self._input_model.get_external_address()
        if address is None:
            logger.warning("Cannot determine address to patch (no selection address stored)")
            return

        logger.debug(
            "Emitting copy_to_db_requested: address=%s, len=%d",
            hex(address),
            len(self._current_output.value),
        )
        self.copy_to_db_requested.emit(address, self._current_output.value)

    def _on_set_comment_clicked(self):
        """Handle set comment at cursor action.

        Emits set_comment_requested signal with comment text.
        """
        comment_text = self._output_display.toPlainText()
        self.set_comment_requested.emit(comment_text)
