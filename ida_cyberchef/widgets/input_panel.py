"""Input panel widget for data entry."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ida_cyberchef.core.hex_formatter import HexFormatter
from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.qt_models.input_model import InputModel, InputSource
from ida_cyberchef.widgets.location_input_widget import LocationInputWidget

try:
    import ida_bytes  # noqa: F401

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


class InputPanel(QWidget):
    """Panel for input data entry and source selection.

    Layout (Manual Input mode):
    ┌─────────────────────────────────────────────────────────────────┐
    │ Input Source: ◉ Manual Input  ○ From Cursor  ○ From Selection  │
    ├─────────────────────────────────────────────────────────────────┤
    │ ┌─ Unified Text Area (editable) ──────────────────────────────┐  │
    │ │ Enter input data...                                        │  │
    │ │                                                            │  │
    │ │                                            [Text (UTF-8)▼] │  │
    │ └────────────────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────────┘

    Layout (From Cursor/Selection mode):
    ┌─────────────────────────────────────────────────────────────────┐
    │ Input Source: ○ Manual Input  ◉ From Cursor  ○ From Selection  │
    ├─────────────────────────────────────────────────────────────────┤
    │ ┌─ Unified Text Area (read-only) ─────────────────────────────┐  │
    │ │ 00000000: 48 65 6c 6c 6f 20 77 6f  72 6c 64     Hello world│  │
    │ │ 00000010: 21 0a                                 !.         │  │
    │ │                                        [Format Disabled ▼] │  │
    │ └────────────────────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────────────────┘
    """

    def __init__(self, input_model: InputModel, parent=None):
        super().__init__(parent)

        self._input_model = input_model
        self._hex_formatter = HexFormatter()
        self._location_widget: LocationInputWidget | None

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup panel UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if IDA_AVAILABLE:
            self._source_widget = QWidget()
            self._source_layout = QHBoxLayout(self._source_widget)
            self._source_layout.setContentsMargins(0, 0, 0, 0)
            self._source_layout.addWidget(QLabel("Input Source:"))

            self._source_group = QButtonGroup(self)

            self._manual_radio = QRadioButton("Manual Input")
            self._manual_radio.setChecked(True)
            self._source_group.addButton(self._manual_radio, 0)
            self._source_layout.addWidget(self._manual_radio)

            self._cursor_radio = QRadioButton("From Cursor")
            self._source_group.addButton(self._cursor_radio, 1)
            self._source_layout.addWidget(self._cursor_radio)

            self._selection_radio = QRadioButton("From Selection")
            self._source_group.addButton(self._selection_radio, 2)
            self._source_layout.addWidget(self._selection_radio)

            self._location_radio = QRadioButton("From Location")
            self._source_group.addButton(self._location_radio, 3)
            self._source_layout.addWidget(self._location_radio)

            self._source_layout.addStretch()
            layout.addWidget(self._source_widget)

            self._location_widget = LocationInputWidget()
            self._location_widget.setVisible(False)
            layout.addWidget(self._location_widget)
        else:
            self._source_widget = None
            self._source_group = None
            self._manual_radio = None
            self._cursor_radio = None
            self._selection_radio = None
            self._location_radio = None
            self._location_widget = None

        self._text_area = QTextEdit()
        self._text_area.setPlaceholderText("Enter input data...")
        self._text_area.setMaximumHeight(90)
        self._text_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._text_area.setStyleSheet("font-family: 'Courier New', Courier, monospace;")
        layout.addWidget(self._text_area)

        self._format_combo = QComboBox(self)
        self._format_combo.addItems(
            [
                "Text (UTF-8)",
                "Hex String",
                "Base64",
            ]
        )
        self._format_combo.setMinimumWidth(150)
        self._format_combo.raise_()

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Reposition overlay combo box on resize."""
        super().resizeEvent(event)

        combo_width = self._format_combo.width()
        combo_height = self._format_combo.height()

        edit_rect = self._text_area.geometry()

        x = edit_rect.right() - combo_width - 6
        y = edit_rect.bottom() - combo_height - 6

        self._format_combo.move(x, y)

    def _connect_signals(self):
        """Connect signals and slots."""
        if self._source_group is not None:
            self._source_group.buttonClicked.connect(self._on_source_changed)

        if self._location_widget is not None:
            self._location_widget.location_changed.connect(
                self._on_location_params_changed
            )

        self._format_combo.currentTextChanged.connect(self._on_format_changed)

        self._text_area.textChanged.connect(self._on_manual_text_changed)

        self._input_model.input_changed.connect(self._on_model_changed)

    def set_location_source(self, address: int, length: int) -> None:
        """Set location-backed input state and sync the UI.

        Args:
            address: Effective address to read from
            length: Number of bytes to read
        """
        self._input_model.set_input_source(InputSource.FROM_LOCATION)

        if self._location_radio is not None:
            self._location_radio.setChecked(True)

        self._on_source_changed()
        self._input_model.set_location_params(address, length)

        if self._location_widget is not None:
            self._location_widget.set_location(address, length)

    def _on_source_changed(self):
        """Handle input source change."""
        if self._manual_radio is None:
            return

        if self._manual_radio.isChecked():
            source = InputSource.MANUAL
            self._text_area.setReadOnly(False)
            self._text_area.setPlaceholderText("Enter input data...")
            self._text_area.setPlainText(self._input_model.get_manual_text())
            self._format_combo.setEnabled(True)
            if self._location_widget is not None:
                self._location_widget.setVisible(False)
        elif self._cursor_radio.isChecked():
            source = InputSource.FROM_CURSOR
            self._text_area.setReadOnly(True)
            self._text_area.setPlaceholderText("")
            self._format_combo.setEnabled(False)
            if self._location_widget is not None:
                self._location_widget.setVisible(False)
            self._update_preview_text()
        elif self._selection_radio.isChecked():
            source = InputSource.FROM_SELECTION
            self._text_area.setReadOnly(True)
            self._text_area.setPlaceholderText("")
            self._format_combo.setEnabled(False)
            if self._location_widget is not None:
                self._location_widget.setVisible(False)
            self._update_preview_text()
        elif self._location_radio.isChecked():
            source = InputSource.FROM_LOCATION
            self._text_area.setReadOnly(True)
            self._text_area.setPlaceholderText("")
            self._format_combo.setEnabled(False)
            if self._location_widget is not None:
                self._location_widget.setVisible(True)
            self._update_preview_text()
        else:
            source = InputSource.MANUAL

        self._input_model.set_input_source(source)

    def _on_format_changed(self):
        """Handle format change."""
        format_name = self._format_combo.currentText()

        if format_name == "Text (UTF-8)":
            format = InputFormat.TEXT_UTF8
        elif format_name == "Hex String":
            format = InputFormat.HEX_STRING
        else:
            format = InputFormat.BASE64

        self._input_model.set_input_format(format)

    def _on_manual_text_changed(self):
        """Handle manual text changes."""
        if not self._text_area.isReadOnly():
            text = self._text_area.toPlainText()
            self._input_model.set_manual_text(text)

    def _on_location_params_changed(self, address: int, length: int):
        """Handle location parameter changes from LocationInputWidget.

        Args:
            address: Effective address
            length: Number of bytes
        """
        self._input_model.set_location_params(address, length)

    def _on_model_changed(self):
        """Handle model changes (external data set)."""
        if self._input_model.get_input_source() != InputSource.MANUAL:
            self._update_preview_text()

    def _update_preview_text(self):
        """Update preview text for external data sources."""
        data = self._input_model.get_input_bytes()
        if data:
            hex_dump = self._hex_formatter.format_hex_dump(data[:256])
            self._text_area.setPlainText(hex_dump)
        else:
            self._text_area.setPlainText("")
