"""Format bytes as hex dump with ASCII preview."""


class HexFormatter:
    """Format bytes as hex dump display."""

    def __init__(self, bytes_per_line: int = 16):
        self.bytes_per_line = bytes_per_line

    def format_hex_dump(self, data: bytes, max_bytes: int = 65536) -> str:
        """Format bytes as hex dump with ASCII column.

        Args:
            data: Bytes to format
            max_bytes: Maximum bytes to format (default 64KB), truncates if exceeded

        Returns: Formatted hex dump string
        """
        original_size = len(data)
        truncated = original_size > max_bytes

        if truncated:
            data = data[:max_bytes]

        lines = []

        for i in range(0, len(data), self.bytes_per_line):
            chunk = data[i : i + self.bytes_per_line]

            # Offset
            offset = f"{i:08x}"

            # Hex bytes
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            # Pad to align ASCII column
            hex_part = hex_part.ljust(self.bytes_per_line * 3 - 1)

            # ASCII representation
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

            lines.append(f"{offset}: {hex_part}  {ascii_part}")

        if truncated:
            lines.append(f"\n... (truncated, showing first {max_bytes:,} of {original_size:,} bytes)")

        return "\n".join(lines)

    def format_hex_string_unspaced(self, data: bytes) -> str:
        """Format bytes as unspaced hex string.

        Args:
            data: Bytes to format

        Returns: Hex string like "48656c6c6f"
        """
        return data.hex()

    def format_hex_string_spaced(self, data: bytes) -> str:
        """Format bytes as spaced hex string.

        Args:
            data: Bytes to format

        Returns: Hex string like "48 65 6c 6c 6f"
        """
        return " ".join(f"{b:02x}" for b in data)

    def format_string_literal(self, data: bytes) -> str:
        """Format bytes as C string literal with escape sequences.

        Args:
            data: Bytes to format

        Returns: String like "Hello\\x00\\x0a"
        """
        result = []
        for b in data:
            if 32 <= b <= 126 and b not in (34, 92):  # Printable ASCII except " and \
                result.append(chr(b))
            elif b == 34:  # Double quote
                result.append('\\"')
            elif b == 92:  # Backslash
                result.append("\\\\")
            elif b == 9:  # Tab
                result.append("\\t")
            elif b == 10:  # Newline
                result.append("\\n")
            elif b == 13:  # Carriage return
                result.append("\\r")
            else:
                result.append(f"\\x{b:02x}")
        return '"' + "".join(result) + '"'

    def format_c_uchar_array_hex(self, data: bytes) -> str:
        """Format bytes as C unsigned char array in hex.

        Args:
            data: Bytes to format

        Returns: String like "0x48, 0x65, 0x6c, 0x6c, 0x6f"
        """
        return ", ".join(f"0x{b:02x}" for b in data)

    def format_c_uchar_array_decimal(self, data: bytes) -> str:
        """Format bytes as C unsigned char array in decimal.

        Args:
            data: Bytes to format

        Returns: String like "72, 101, 108, 108, 111"
        """
        return ", ".join(str(b) for b in data)

    def format_c_initialized_variable(self, data: bytes) -> str:
        """Format bytes as initialized C variable declaration.

        Args:
            data: Bytes to format

        Returns: Multi-line C variable declaration
        """
        if not data:
            return "unsigned char data[] = {};"

        # Format as hex bytes, 12 per line for readability
        hex_bytes = [f"0x{b:02x}" for b in data]
        lines = []
        lines.append(f"unsigned char data[{len(data)}] = {{")

        for i in range(0, len(hex_bytes), 12):
            chunk = hex_bytes[i : i + 12]
            line = "    " + ", ".join(chunk)
            if i + 12 < len(hex_bytes):
                line += ","
            lines.append(line)

        lines.append("};")
        return "\n".join(lines)
