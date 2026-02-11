"""Tests for configuration management."""

import tempfile
from pathlib import Path

from agentshell.config import Config


def test_save_and_load():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cfg = Config()
        cfg.server.port = 9999
        cfg.server.password_hash = "fakehash"
        cfg.server.shell_command = "bash"
        cfg.save(tmp)

        loaded = Config.load(tmp)
        assert loaded.server.port == 9999
        assert loaded.server.password_hash == "fakehash"
        assert loaded.server.shell_command == "bash"


def test_defaults():
    cfg = Config()
    assert cfg.server.port == 7920
    assert cfg.server.shell_command == "claude"
    assert cfg.server.max_sessions == 3
    assert cfg.server.totp_enabled is False


def test_load_missing_returns_defaults():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config.load(Path(tmp))
        assert cfg.server.port == 7920
