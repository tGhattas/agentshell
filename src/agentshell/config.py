"""Configuration management for AgentShell."""

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def _default_config_dir() -> Path:
    """Get the default configuration directory."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".config"
    return base / "agentshell"


@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 7920
    shell_command: str = "claude"
    max_sessions: int = 3
    idle_timeout: int = 3600  # seconds
    password_hash: str = ""
    totp_secret: str = ""
    totp_enabled: bool = False
    cert_fingerprint: str = ""

    # Rate-limiting for failed auth attempts
    max_auth_failures: int = 5
    auth_lockout_seconds: int = 300


@dataclass
class ClientConfig:
    server_host: str = "localhost"
    server_port: int = 7920
    cert_fingerprint: str = ""
    ca_cert_path: str = ""


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    client: ClientConfig = field(default_factory=ClientConfig)

    @classmethod
    def load(cls, config_dir: Path | None = None) -> "Config":
        """Load configuration from disk, or return defaults."""
        config_dir = config_dir or _default_config_dir()
        config_file = config_dir / "config.json"
        if not config_file.exists():
            return cls()
        data = json.loads(config_file.read_text())
        server_data = data.get("server", {})
        client_data = data.get("client", {})
        return cls(
            server=ServerConfig(**{
                k: v for k, v in server_data.items()
                if k in ServerConfig.__dataclass_fields__
            }),
            client=ClientConfig(**{
                k: v for k, v in client_data.items()
                if k in ClientConfig.__dataclass_fields__
            }),
        )

    def save(self, config_dir: Path | None = None) -> Path:
        """Save configuration to disk."""
        config_dir = config_dir or _default_config_dir()
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.json"
        data: dict[str, Any] = {
            "server": asdict(self.server),
            "client": asdict(self.client),
        }
        config_file.write_text(json.dumps(data, indent=2) + "\n")
        config_file.chmod(0o600)
        return config_file

    @staticmethod
    def config_dir(override: Path | None = None) -> Path:
        return override or _default_config_dir()

    @staticmethod
    def cert_path(config_dir: Path | None = None) -> Path:
        return (config_dir or _default_config_dir()) / "server.crt"

    @staticmethod
    def key_path(config_dir: Path | None = None) -> Path:
        return (config_dir or _default_config_dir()) / "server.key"
