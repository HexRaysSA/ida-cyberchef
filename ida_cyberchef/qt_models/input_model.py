"""Qt model for input data management."""

import logging
from enum import IntEnum
from typing import Optional

from PySide6.QtCore import QObject, Signal

from ida_cyberchef.core.input_parser import InputFormat, InputParser

logger = logging.getLogger(__name__)

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
    location_params_changed = Signal("quint64", "quint64")
    parse_error_changed = Signal(object)

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
        self._manual_parse_result = self._parser.parse(self._manual_text, self._format)

    def get_input_source(self) -> InputSource:
        """Get current input source type."""
        return self._source

    def set_input_source(self, source: InputSource):
        """Set input source type."""
        if self._source != source:
            previous_error = self.get_parse_error()
            self._source = source
            self.source_changed.emit(source)
            self._emit_parse_error_if_changed(previous_error)
            self.input_changed.emit()

    def get_input_format(self) -> InputFormat:
        """Get current input format (for manual input only)."""
        return self._format

    def set_input_format(self, format: InputFormat):
        """Set input format for manual input."""
        if self._format != format:
            previous_error = self.get_parse_error()
            self._format = format
            self._manual_parse_result = self._parser.parse(self._manual_text, self._format)
            self._emit_parse_error_if_changed(previous_error)
            self.input_changed.emit()

    def set_manual_text(self, text: str):
        """Set manual input text."""
        if self._manual_text != text:
            previous_error = self.get_parse_error()
            self._manual_text = text
            self._manual_parse_result = self._parser.parse(self._manual_text, self._format)
            self._emit_parse_error_if_changed(previous_error)
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

    def clear_external_data(self):
        """Clear external input data (from cursor/selection)."""
        self._external_data = None
        self._external_address = None
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
            return self._manual_parse_result.data
        elif self._source == InputSource.FROM_LOCATION:
            return self._location_data if self._location_data else b""
        else:
            return self._external_data

    def get_parse_error(self) -> Optional[str]:
        """Get the current visible parse error for manual input, if any."""
        if self._source != InputSource.MANUAL:
            return None
        return self._manual_parse_result.error

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
                if data:
                    self._location_data = data
                else:
                    logger.warning(
                        "ida_bytes.get_bytes(0x%x, %d) returned empty data",
                        address,
                        length,
                    )
                    self._location_data = b""
            except Exception:
                logger.error(
                    "failed to read %d bytes at 0x%x",
                    length,
                    address,
                    exc_info=True,
                )
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

    def _emit_parse_error_if_changed(self, previous_error: Optional[str]) -> None:
        """Emit parse_error_changed when the visible parse error changes."""
        current_error = self.get_parse_error()
        if current_error != previous_error:
            self.parse_error_changed.emit(current_error)
