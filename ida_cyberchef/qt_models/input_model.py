"""Qt model for input data management."""

from enum import IntEnum
from typing import Optional

from PySide6.QtCore import QObject, Signal

from ida_cyberchef.core.input_parser import InputFormat, InputParser

try:
    import ida_bytes

    IDA_AVAILABLE = True
except ImportError:
    ida_bytes = None  # type: ignore
    IDA_AVAILABLE = False


class InputSource(IntEnum):
    """Input data source types."""

    MANUAL = 0
    FROM_CURSOR = 1
    FROM_SELECTION = 2
    FROM_LOCATION = 3


class InputModel(QObject):
    """Manages input data source and format."""

    input_changed = Signal()
    source_changed = Signal(InputSource)
    location_params_changed = Signal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)

        self._source = InputSource.MANUAL
        self._format = InputFormat.TEXT_UTF8
        self._manual_text = ""
        self._external_data: Optional[bytes] = None
        self._external_address: Optional[int] = None

        self._location_address: Optional[int] = None
        self._location_length: Optional[int] = None
        self._location_data: Optional[bytes] = None

        self._parser = InputParser()

    def get_input_source(self) -> InputSource:
        """Get current input source type."""
        return self._source

    def set_input_source(self, source: InputSource):
        """Set input source type."""
        if self._source != source:
            self._source = source
            self.source_changed.emit(source)
            self.input_changed.emit()

    def get_input_format(self) -> InputFormat:
        """Get current input format (for manual input only)."""
        return self._format

    def set_input_format(self, format: InputFormat):
        """Set input format for manual input."""
        if self._format != format:
            self._format = format
            self.input_changed.emit()

    def set_manual_text(self, text: str):
        """Set manual input text."""
        if self._manual_text != text:
            self._manual_text = text
            self.input_changed.emit()

    def get_manual_text(self) -> str:
        """Get current manual input text."""
        return self._manual_text

    def set_external_data(self, data: bytes, address: Optional[int] = None):
        """Set external input data (from cursor/selection).

        Args:
            data: The bytes data
            address: Optional address where the data came from
        """
        self._external_data = data
        self._external_address = address
        self.input_changed.emit()

    def get_external_address(self) -> Optional[int]:
        """Get the address where external data came from.

        Returns: Address if set, None otherwise
        """
        if self._source == InputSource.FROM_LOCATION:
            return self._location_address
        return self._external_address

    def get_input_bytes(self) -> Optional[bytes]:
        """Get current input as bytes based on source and format.

        Returns: Input bytes, or None if parsing fails
        """
        if self._source == InputSource.MANUAL:
            return self._parser.parse(self._manual_text, self._format)
        elif self._source == InputSource.FROM_LOCATION:
            return self._location_data if self._location_data else b""
        else:
            return self._external_data

    def set_location_params(self, address: int, length: int):
        """Set location parameters and fetch data from IDA.

        Only used when source == FROM_LOCATION.

        Args:
            address: Effective address to read from
            length: Number of bytes to read
        """
        self._location_address = address
        self._location_length = length

        if IDA_AVAILABLE:
            try:
                data = ida_bytes.get_bytes(address, length)
                self._location_data = data if data else b""
            except Exception:
                self._location_data = b""
        else:
            self._location_data = b""

        self.location_params_changed.emit(address, length)
        self.input_changed.emit()

    def get_location_address(self) -> Optional[int]:
        """Get location address (only valid when source == FROM_LOCATION)."""
        return self._location_address

    def get_location_length(self) -> Optional[int]:
        """Get location length (only valid when source == FROM_LOCATION)."""
        return self._location_length
