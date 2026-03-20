"""Widget for address and length input in FROM_LOCATION mode."""

import logging

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QWidget

logger = logging.getLogger(__name__)

VALID_STYLE = "font-family: 'Courier New', Courier, monospace;"
INVALID_STYLE = "font-family: 'Courier New', Courier, monospace; border: 1px solid red;"


class LocationInputWidget(QWidget):
    """Widget for inputting location parameters (address and length).

    Layout:
    ┌─────────────────────────────────────────────────┐
    │ Address: [0x00401000          ] Length: [256  ] │
    └─────────────────────────────────────────────────┘
    """

    location_changed = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Setup widget UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QLabel("Address:"))

        self._address_edit = QLineEdit()
        self._address_edit.setPlaceholderText("0x00000000")
        self._address_edit.setStyleSheet(VALID_STYLE)
        self._address_edit.setMinimumWidth(120)
        layout.addWidget(self._address_edit)

        layout.addWidget(QLabel("Length:"))

        self._length_edit = QLineEdit()
        self._length_edit.setText("256")
        self._length_edit.setStyleSheet(VALID_STYLE)
        self._length_edit.setMinimumWidth(80)
        layout.addWidget(self._length_edit)

        layout.addStretch()

    def _connect_signals(self):
        """Connect signals and slots."""
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(300)
        self._debounce_timer.timeout.connect(self._on_params_changed)

        self._address_edit.textChanged.connect(self._schedule_update)
        self._length_edit.textChanged.connect(self._schedule_update)

    def _schedule_update(self):
        """Restart debounce timer on any text change."""
        self._debounce_timer.start()

    def _parse_address(self, text: str) -> int | None:
        """Parse address text as hexadecimal."""
        text = text.strip()
        if not text:
            return None
        try:
            if text.startswith(("0x", "0X")):
                return int(text, 16)
            return int(text, 16)
        except ValueError:
            return None

    def _parse_length(self, text: str) -> int | None:
        """Parse length text as decimal."""
        text = text.strip()
        if not text:
            return None
        try:
            value = int(text, 10)
            return value if value > 0 else None
        except ValueError:
            return None

    def _on_params_changed(self):
        """Handle parameter changes with validation and visual feedback."""
        address_text = self._address_edit.text()
        length_text = self._length_edit.text()

        address = self._parse_address(address_text)
        length = self._parse_length(length_text)

        if address_text.strip():
            if address is None:
                self._address_edit.setStyleSheet(INVALID_STYLE)
                logger.warning("invalid address value: %r", address_text.strip())
            else:
                self._address_edit.setStyleSheet(VALID_STYLE)
        else:
            self._address_edit.setStyleSheet(VALID_STYLE)

        if length_text.strip():
            if length is None:
                self._length_edit.setStyleSheet(INVALID_STYLE)
                logger.warning("invalid length value: %r", length_text.strip())
            else:
                self._length_edit.setStyleSheet(VALID_STYLE)
        else:
            self._length_edit.setStyleSheet(VALID_STYLE)

        if address is not None and length is not None:
            self.location_changed.emit(address, length)

    def set_location(self, address: int, length: int):
        """Set address and length fields programmatically.

        Args:
            address: Effective address
            length: Number of bytes
        """
        self._address_edit.setText(f"0x{address:08x}")
        self._length_edit.setText(str(length))
