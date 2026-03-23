"""Parse various input formats into bytes."""

import base64
from dataclasses import dataclass
from enum import Enum


class InputFormat(Enum):
    """Supported input format types."""

    TEXT_UTF8 = "text_utf8"
    HEX_STRING = "hex_string"
    BASE64 = "base64"


@dataclass(frozen=True)
class ParseResult:
    """Result of parsing user input."""

    data: bytes | None
    error: str | None = None

    @property
    def success(self) -> bool:
        """Return True when parsing succeeded."""
        return self.error is None


class InputParser:
    """Parse text input into bytes based on format."""

    def parse(self, text: str, format: InputFormat) -> ParseResult:
        """Parse text input into bytes.

        Args:
            text: Input text
            format: Format type

        Returns: Structured parse result
        """
        try:
            if format == InputFormat.TEXT_UTF8:
                return ParseResult(data=text.encode("utf-8"))

            elif format == InputFormat.HEX_STRING:
                hex_str = text.replace(" ", "").replace(":", "").replace("-", "")
                return ParseResult(data=bytes.fromhex(hex_str))

            elif format == InputFormat.BASE64:
                normalized = "".join(text.split())
                return ParseResult(data=base64.b64decode(normalized, validate=True))

        except Exception as exc:
            return ParseResult(data=None, error=str(exc))

        return ParseResult(data=None, error=f"Unsupported input format: {format}")
