"""WebSocket server — authenticates clients and bridges them to PTY sessions."""

import asyncio
import logging
import time
from pathlib import Path

import websockets
from websockets.asyncio.server import ServerConnection

from agentshell import auth, protocol
from agentshell.config import Config, ServerConfig
from agentshell.session import PtySession, pty_read_loop
from agentshell.tls import create_server_ssl_context

logger = logging.getLogger("agentshell.server")


class AuthTracker:
    """Track failed authentication attempts for rate limiting."""

    def __init__(self, max_failures: int, lockout_seconds: int):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        # ip -> (failure_count, first_failure_time)
        self._failures: dict[str, tuple[int, float]] = {}

    def is_locked(self, ip: str) -> bool:
        if ip not in self._failures:
            return False
        count, first_time = self._failures[ip]
        if count >= self.max_failures:
            if time.monotonic() - first_time < self.lockout_seconds:
                return True
            # Lockout expired
            del self._failures[ip]
            return False
        return False

    def record_failure(self, ip: str) -> None:
        now = time.monotonic()
        if ip in self._failures:
            count, first_time = self._failures[ip]
            if now - first_time > self.lockout_seconds:
                self._failures[ip] = (1, now)
            else:
                self._failures[ip] = (count + 1, first_time)
        else:
            self._failures[ip] = (1, now)

    def clear(self, ip: str) -> None:
        self._failures.pop(ip, None)


class AgentShellServer:
    """The main server that manages authenticated PTY sessions over WebSocket."""

    def __init__(self, config: Config, config_dir: Path | None = None):
        self.config = config
        self.sc = config.server
        self.config_dir = config_dir or Config.config_dir()
        self.auth_tracker = AuthTracker(
            self.sc.max_auth_failures,
            self.sc.auth_lockout_seconds,
        )
        self._active_sessions: int = 0
        self._lock = asyncio.Lock()

    async def _authenticate(
        self, ws: ServerConnection, remote_ip: str
    ) -> bool:
        """Handle the authentication handshake. Returns True on success."""
        if self.auth_tracker.is_locked(remote_ip):
            await ws.send(protocol.auth_response(
                ok=False,
                error="Too many failed attempts. Try again later.",
            ))
            return False

        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=30)
        except (asyncio.TimeoutError, websockets.ConnectionClosed):
            return False

        if isinstance(raw, bytes):
            await ws.send(protocol.auth_response(
                ok=False, error="Expected JSON auth message"
            ))
            return False

        try:
            msg = protocol.decode_control(raw)
        except (ValueError, Exception):
            await ws.send(protocol.auth_response(
                ok=False, error="Invalid message format"
            ))
            return False

        if msg.get("type") != protocol.MsgType.AUTH.value:
            await ws.send(protocol.auth_response(
                ok=False, error="Expected auth message"
            ))
            return False

        password = msg.get("password", "")
        totp_code = msg.get("totp", "")

        # Verify password
        if not auth.verify_password(self.sc.password_hash, password):
            self.auth_tracker.record_failure(remote_ip)
            logger.warning("Auth failure from %s (bad password)", remote_ip)
            await ws.send(protocol.auth_response(
                ok=False, error="Authentication failed"
            ))
            return False

        # Verify TOTP if enabled
        if self.sc.totp_enabled:
            if not totp_code or not auth.verify_totp(self.sc.totp_secret, totp_code):
                self.auth_tracker.record_failure(remote_ip)
                logger.warning("Auth failure from %s (bad TOTP)", remote_ip)
                await ws.send(protocol.auth_response(
                    ok=False, error="Authentication failed"
                ))
                return False

        self.auth_tracker.clear(remote_ip)
        await ws.send(protocol.auth_response(ok=True))
        logger.info("Authenticated client from %s", remote_ip)
        return True

    async def _handle_session(self, ws: ServerConnection) -> None:
        """Handle a single authenticated WebSocket session."""
        remote = ws.request.headers.get(
            "X-Forwarded-For",
            ws.remote_address[0] if ws.remote_address else "unknown",
        )
        remote_ip = str(remote).split(",")[0].strip()

        logger.info("Connection from %s", remote_ip)

        # Authenticate
        if not await self._authenticate(ws, remote_ip):
            return

        # Check session limit
        async with self._lock:
            if self._active_sessions >= self.sc.max_sessions:
                await ws.send(protocol.error_msg(
                    "Maximum sessions reached. Try again later."
                ))
                return
            self._active_sessions += 1

        session = PtySession(
            command=self.sc.shell_command,
            env={"AGENTSHELL": "1"},
        )

        try:
            session.spawn(rows=24, cols=80)
            logger.info("Spawned PTY session for %s: %s", remote_ip, self.sc.shell_command)

            # Forward PTY output -> WebSocket (binary frames)
            async def send_pty_output(data: bytes) -> None:
                try:
                    await ws.send(data)
                except websockets.ConnectionClosed:
                    pass

            read_task = asyncio.create_task(
                pty_read_loop(session, send_pty_output)
            )

            # Forward WebSocket input -> PTY
            try:
                async for message in ws:
                    if isinstance(message, bytes):
                        # Terminal input data
                        session.write(message)
                    elif isinstance(message, str):
                        # Control message
                        try:
                            msg = protocol.decode_control(message)
                        except ValueError:
                            continue

                        msg_type = msg.get("type")
                        if msg_type == protocol.MsgType.RESIZE.value:
                            rows = msg.get("rows", 24)
                            cols = msg.get("cols", 80)
                            session.resize(rows, cols)
                        elif msg_type == protocol.MsgType.PING.value:
                            await ws.send(
                                protocol.encode_control(protocol.MsgType.PONG)
                            )
            except websockets.ConnectionClosed:
                logger.info("Client %s disconnected", remote_ip)
            finally:
                read_task.cancel()
                try:
                    await read_task
                except (asyncio.CancelledError, Exception):
                    pass
        finally:
            session.close()
            async with self._lock:
                self._active_sessions -= 1
            logger.info("Session ended for %s", remote_ip)

    async def serve(self) -> None:
        """Start the WebSocket server."""
        cert_path = Config.cert_path(self.config_dir)
        key_path = Config.key_path(self.config_dir)

        if not cert_path.exists() or not key_path.exists():
            raise FileNotFoundError(
                "TLS certificate not found. Run 'agentshell init' first."
            )

        ssl_ctx = create_server_ssl_context(cert_path, key_path)

        logger.info(
            "Starting AgentShell server on %s:%d (TLS)",
            self.sc.host,
            self.sc.port,
        )
        logger.info("Shell command: %s", self.sc.shell_command)
        logger.info("Max sessions: %d", self.sc.max_sessions)
        logger.info("TOTP 2FA: %s", "enabled" if self.sc.totp_enabled else "disabled")

        async with websockets.serve(
            self._handle_session,
            self.sc.host,
            self.sc.port,
            ssl=ssl_ctx,
            max_size=1_048_576,  # 1 MB max message
            ping_interval=30,
            ping_timeout=10,
        ):
            logger.info("Server is ready. Waiting for connections...")
            await asyncio.Future()  # Run forever
