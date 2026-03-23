"""Widget for address and length input in FROM_LOCATION mode."""

import logging

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QLineEdit, QWidget

logger = logging.getLogger(__name__)

VALID_STYLE = "font-family: 'Courier New', Courier, monospace;"
INVALID_STYLE = "font-family: 'Courier New', Courier, monospace; border: 1px solid red;"

MODE_LENGTH = 0
MODE_END_ADDRESS = 1


class LocationInputWidget(QWidget):
    """Widget for inputting location parameters (address and length or end address).

    Layout (length mode):
    ┌──────────────────────────────────────────────────────────┐
    │ Address: [0x00401000    ] [Length ▾]: [256    ]           │
    └──────────────────────────────────────────────────────────┘

    Layout (end address mode):
    ┌──────────────────────────────────────────────────────────┐
    │ Address: [0x00401000    ] [End Addr ▾]: [0x00401100    ] │
    └──────────────────────────────────────────────────────────┘
    """

    location_changed = Signal('quint64', 'quint64')

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        layout.addWidget(QLabel("Address:"))

        self._address_edit = QLineEdit()
        self._address_edit.setPlaceholderText("0x00000000")
        self._address_edit.setStyleSheet(VALID_STYLE)
        self._address_edit.setMinimumWidth(120)
        layout.addWidget(self._address_edit)

        self._mode_combo = QComboBox()
        self._mode_combo.addItem("Length:", MODE_LENGTH)
        self._mode_combo.addItem("End Addr:", MODE_END_ADDRESS)
        layout.addWidget(self._mode_combo)

        self._length_edit = QLineEdit()
        self._length_edit.setText("256")
        self._length_edit.setStyleSheet(VALID_STYLE)
        self._length_edit.setMinimumWidth(80)
        layout.addWidget(self._length_edit)

        self._end_addr_edit = QLineEdit()
        self._end_addr_edit.setPlaceholderText("0x00000000")
        self._end_addr_edit.setStyleSheet(VALID_STYLE)
        self._end_addr_edit.setMinimumWidth(120)
        self._end_addr_edit.hide()
        layout.addWidget(self._end_addr_edit)

        layout.addStretch()

    def _connect_signals(self):
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(300)
        self._debounce_timer.timeout.connect(self._on_params_changed)

        self._address_edit.textChanged.connect(self._schedule_update)
        self._length_edit.textChanged.connect(self._schedule_update)
        self._end_addr_edit.textChanged.connect(self._schedule_update)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)

    def _on_mode_changed(self, index: int):
        if index == MODE_LENGTH:
            self._end_addr_edit.hide()
            self._length_edit.show()
        else:
            self._length_edit.hide()
            self._end_addr_edit.show()
        self._schedule_update()

    def _schedule_update(self):
        self._debounce_timer.start()

    def _parse_address(self, text: str) -> int | None:
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
        text = text.strip()
        if not text:
            return None
        try:
            value = int(text, 10)
            return value if value > 0 else None
        except ValueError:
            return None

    def _compute_length(self, address: int | None) -> int | None:
        """Compute length from either length field or end address field."""
        if self._mode_combo.currentIndex() == MODE_LENGTH:
            length_text = self._length_edit.text()
            length = self._parse_length(length_text)
            if length_text.strip():
                self._length_edit.setStyleSheet(
                    INVALID_STYLE if length is None else VALID_STYLE
                )
                if length is None:
                    logger.warning("invalid length value: %r", length_text.strip())
            else:
                self._length_edit.setStyleSheet(VALID_STYLE)
            return length
        else:
            end_text = self._end_addr_edit.text()
            end_addr = self._parse_address(end_text)
            if end_text.strip():
                if end_addr is None or (address is not None and end_addr <= address):
                    self._end_addr_edit.setStyleSheet(INVALID_STYLE)
                    if end_addr is None:
                        logger.warning("invalid end address value: %r", end_text.strip())
                    elif address is not None:
                        logger.warning("end address must be greater than start address")
                    return None
                else:
                    self._end_addr_edit.setStyleSheet(VALID_STYLE)
            else:
                self._end_addr_edit.setStyleSheet(VALID_STYLE)
                return None
            if address is not None and end_addr is not None:
                return end_addr - address
            return None

    def _on_params_changed(self):
        address_text = self._address_edit.text()
        address = self._parse_address(address_text)

        if address_text.strip():
            if address is None:
                self._address_edit.setStyleSheet(INVALID_STYLE)
                logger.warning("invalid address value: %r", address_text.strip())
            else:
                self._address_edit.setStyleSheet(VALID_STYLE)
        else:
            self._address_edit.setStyleSheet(VALID_STYLE)

        length = self._compute_length(address)

        if address is not None and length is not None:
            self.location_changed.emit(address, length)

    def set_location(self, address: int, length: int):
        """Set address and length fields programmatically.

        Args:
            address: Effective address
            length: Number of bytes
        """
        self._address_edit.setText(f"0x{address:08x}")
        if self._mode_combo.currentIndex() == MODE_END_ADDRESS:
            self._end_addr_edit.setText(f"0x{address + length:08x}")
        else:
            self._length_edit.setText(str(length))
