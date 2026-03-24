from ida_cyberchef.core.input_parser import InputFormat
from ida_cyberchef.qt_models.input_model import InputModel, InputSource


def test_create_input_model():
    model = InputModel()

    assert model.get_input_source() == InputSource.MANUAL
    assert model.get_input_format() == InputFormat.TEXT_UTF8


def test_set_manual_text():
    model = InputModel()
    model.set_manual_text("Hello")

    data = model.get_input_bytes()
    assert data == b"Hello"


def test_set_input_format():
    model = InputModel()
    model.set_input_format(InputFormat.HEX_STRING)
    model.set_manual_text("48656c6c6f")

    data = model.get_input_bytes()
    assert data == b"Hello"


def test_set_external_data():
    model = InputModel()
    model.set_input_source(InputSource.FROM_CURSOR)
    model.set_external_data(b"External")

    data = model.get_input_bytes()
    assert data == b"External"


def test_clear_external_data(qtbot):
    model = InputModel()
    model.set_input_source(InputSource.FROM_SELECTION)
    model.set_external_data(b"External", address=0x401000)

    assert model.get_input_bytes() == b"External"
    assert model.get_external_address() == 0x401000

    with qtbot.waitSignal(model.input_changed):
        model.clear_external_data()

    assert model.get_input_bytes() is None
    assert model.get_external_address() is None


def test_input_changed_signal(qtbot):
    model = InputModel()

    with qtbot.waitSignal(model.input_changed):
        model.set_manual_text("Test")


def test_source_changed_signal_emitted():
    model = InputModel()
    received = []
    model.source_changed.connect(lambda source: received.append(source))

    model.set_input_source(InputSource.FROM_CURSOR)

    assert len(received) == 1
    assert received[0] == InputSource.FROM_CURSOR


def test_source_changed_not_emitted_when_same():
    model = InputModel()
    model.set_input_source(InputSource.MANUAL)
    received = []
    model.source_changed.connect(lambda source: received.append(source))

    model.set_input_source(InputSource.MANUAL)

    assert len(received) == 0


def test_input_source_from_location_exists():
    assert hasattr(InputSource, "FROM_LOCATION")
    assert InputSource.FROM_LOCATION == 3


def test_location_fields_and_methods():
    model = InputModel()
    # Should have methods for location params
    assert hasattr(model, "set_location_params")
    assert hasattr(model, "get_location_address")
    assert hasattr(model, "get_location_length")
    # Initial state should be None
    assert model.get_location_address() is None
    assert model.get_location_length() is None


def test_set_location_params_fetches_ida_bytes(monkeypatch):
    """Test that set_location_params fetches bytes from IDA."""
    mock_bytes = b"\x48\x65\x6c\x6c\x6f"

    def mock_get_bytes(address, length):
        assert address == 0x401000
        assert length == 5
        return mock_bytes

    import types
    from typing import Any

    import ida_cyberchef.qt_models.input_model as model_module

    mock_ida_bytes: Any = types.ModuleType("ida_bytes")
    mock_ida_bytes.get_bytes = mock_get_bytes
    monkeypatch.setattr(model_module, "ida_bytes", mock_ida_bytes)
    monkeypatch.setattr(model_module, "IDA_AVAILABLE", True)

    model = InputModel()
    model.set_location_params(0x401000, 5)

    assert model.get_location_address() == 0x401000
    assert model.get_location_length() == 5
    assert model._location_data == mock_bytes


def test_manual_parse_error_is_tracked_and_cleared(qtbot):
    model = InputModel()
    model.set_input_format(InputFormat.HEX_STRING)

    with qtbot.waitSignal(model.parse_error_changed, timeout=1000) as invalid_signal:
        model.set_manual_text("zz")

    assert invalid_signal.args == [model.get_parse_error()]
    assert model.get_parse_error() is not None
    assert model.get_input_bytes() is None

    with qtbot.waitSignal(model.parse_error_changed, timeout=1000) as valid_signal:
        model.set_manual_text("41")

    assert valid_signal.args == [None]
    assert model.get_parse_error() is None
    assert model.get_input_bytes() == b"A"


def test_parse_error_hidden_for_non_manual_sources(qtbot):
    model = InputModel()
    model.set_input_format(InputFormat.HEX_STRING)
    model.set_manual_text("zz")
    assert model.get_parse_error() is not None

    with qtbot.waitSignal(model.parse_error_changed, timeout=1000) as hidden_signal:
        model.set_input_source(InputSource.FROM_CURSOR)

    assert hidden_signal.args == [None]
    assert model.get_parse_error() is None
