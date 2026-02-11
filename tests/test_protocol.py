"""Tests for the wire protocol."""

import pytest

from agentshell.protocol import (
    MsgType,
    auth_request,
    auth_response,
    decode_control,
    encode_control,
    error_msg,
    resize_msg,
)


def test_auth_request():
    msg = auth_request("mypass", "123456")
    d = decode_control(msg)
    assert d["type"] == "auth"
    assert d["password"] == "mypass"
    assert d["totp"] == "123456"


def test_auth_response_ok():
    msg = auth_response(ok=True)
    d = decode_control(msg)
    assert d["ok"] is True


def test_auth_response_fail():
    msg = auth_response(ok=False, error="bad password")
    d = decode_control(msg)
    assert d["ok"] is False
    assert d["error"] == "bad password"


def test_resize():
    msg = resize_msg(40, 120)
    d = decode_control(msg)
    assert d["rows"] == 40
    assert d["cols"] == 120


def test_error_msg():
    msg = error_msg("something broke")
    d = decode_control(msg)
    assert d["type"] == "error"
    assert d["message"] == "something broke"


def test_decode_missing_type():
    with pytest.raises(ValueError):
        decode_control('{"foo": "bar"}')
