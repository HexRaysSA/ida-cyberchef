from ida_cyberchef.core.input_parser import InputFormat, InputParser


def test_parse_text_utf8():
    parser = InputParser()
    result = parser.parse("Hello", InputFormat.TEXT_UTF8)

    assert result.success is True
    assert result.data == b"Hello"
    assert result.error is None


def test_parse_hex_string():
    parser = InputParser()
    result = parser.parse("48656c6c6f", InputFormat.HEX_STRING)

    assert result.success is True
    assert result.data == b"Hello"
    assert result.error is None


def test_parse_hex_with_spaces():
    parser = InputParser()
    result = parser.parse("48 65 6c 6c 6f", InputFormat.HEX_STRING)

    assert result.success is True
    assert result.data == b"Hello"
    assert result.error is None


def test_parse_base64():
    parser = InputParser()
    result = parser.parse("SGVsbG8=", InputFormat.BASE64)

    assert result.success is True
    assert result.data == b"Hello"
    assert result.error is None


def test_parse_base64_ignores_whitespace():
    parser = InputParser()
    result = parser.parse("SGVs\nbG8=\t", InputFormat.BASE64)

    assert result.success is True
    assert result.data == b"Hello"
    assert result.error is None


def test_parse_invalid_base64():
    parser = InputParser()
    result = parser.parse("SGVsbG8*", InputFormat.BASE64)

    assert result.success is False
    assert result.data is None
    assert result.error is not None


def test_parse_invalid_hex():
    parser = InputParser()
    result = parser.parse("not hex", InputFormat.HEX_STRING)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
