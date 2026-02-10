"""Wire protocol for AgentShell WebSocket communication.

Message types (JSON text frames):
  - auth_request:  client -> server  {"type":"auth","password":"...","totp":"..."}
  - auth_response: server -> client  {"type":"auth_result","ok":bool,"error":"..."}
  - resize:        client -> server  {"type":"resize","rows":N,"cols":N}
  - ping/pong:     bidirectional     {"type":"ping"} / {"type":"pong"}
  - error:         server -> client  {"type":"error","message":"..."}

Binary frames:
  - Terminal data (stdin from client, stdout from server) is sent as raw
    binary WebSocket frames for efficiency.
"""

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class MsgType(str, Enum):
    AUTH = "auth"
    AUTH_RESULT = "auth_result"
    RESIZE = "resize"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"


def encode_control(msg_type: MsgType, **kwargs: Any) -> str:
    """Encode a control message as JSON."""
    return json.dumps({"type": msg_type.value, **kwargs})


def decode_control(raw: str) -> dict[str, Any]:
    """Decode a JSON control message."""
    data = json.loads(raw)
    if "type" not in data:
        raise ValueError("Missing 'type' field in control message")
    return data


def auth_request(password: str, totp: str = "") -> str:
    return encode_control(MsgType.AUTH, password=password, totp=totp)


def auth_response(ok: bool, error: str = "") -> str:
    return encode_control(MsgType.AUTH_RESULT, ok=ok, error=error)


def resize_msg(rows: int, cols: int) -> str:
    return encode_control(MsgType.RESIZE, rows=rows, cols=cols)


def error_msg(message: str) -> str:
    return encode_control(MsgType.ERROR, message=message)
