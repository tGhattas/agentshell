"""WebSocket client — connects to a remote AgentShell server."""

import asyncio
import getpass
import os
import signal
import ssl
import struct
import sys
import termios
import tty
from pathlib import Path

import websockets

from agentshell import protocol
from agentshell.tls import create_client_ssl_context, get_cert_fingerprint


async def connect(
    host: str,
    port: int,
    password: str | None = None,
    totp_code: str | None = None,
    fingerprint: str | None = None,
    ca_cert: Path | None = None,
) -> None:
    """Connect to an AgentShell server and provide interactive terminal access."""

    uri = f"wss://{host}:{port}"

    # Build SSL context
    ssl_ctx = create_client_ssl_context(
        expected_fingerprint=fingerprint,
        ca_cert_path=ca_cert,
    )

    # Prompt for credentials if not provided
    if password is None:
        password = getpass.getpass("Password: ")
    if totp_code is None:
        totp_code = ""

    print(f"Connecting to {uri}...")

    try:
        async with websockets.connect(
            uri,
            ssl=ssl_ctx,
            max_size=1_048_576,
            ping_interval=30,
            ping_timeout=10,
            server_hostname=host,
        ) as ws:
            # Certificate fingerprint verification
            if fingerprint:
                peer_cert_der = ws.transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
                if peer_cert_der:
                    import hashlib
                    actual_fp = hashlib.sha256(peer_cert_der).hexdigest()
                    actual_fp_fmt = ":".join(
                        actual_fp[i:i+2] for i in range(0, len(actual_fp), 2)
                    )
                    if actual_fp_fmt.lower() != fingerprint.lower():
                        print(
                            f"\nCERTIFICATE MISMATCH!\n"
                            f"  Expected: {fingerprint}\n"
                            f"  Got:      {actual_fp_fmt}\n"
                            f"Connection refused.",
                            file=sys.stderr,
                        )
                        return

            # Authenticate
            await ws.send(protocol.auth_request(password, totp_code))

            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=15)
            except asyncio.TimeoutError:
                print("Authentication timed out.", file=sys.stderr)
                return

            if isinstance(raw, bytes):
                print("Unexpected binary response during auth.", file=sys.stderr)
                return

            msg = protocol.decode_control(raw)
            if not msg.get("ok"):
                print(
                    f"Authentication failed: {msg.get('error', 'unknown error')}",
                    file=sys.stderr,
                )
                return

            print("Authenticated. Starting remote session...")
            print("Press Ctrl+] to disconnect.\n")

            await _run_terminal(ws)

    except ConnectionRefusedError:
        print(f"Connection refused: {uri}", file=sys.stderr)
    except ssl.SSLError as e:
        print(f"TLS error: {e}", file=sys.stderr)
    except OSError as e:
        print(f"Connection error: {e}", file=sys.stderr)


async def _run_terminal(ws: websockets.ClientConnection) -> None:
    """Run the interactive terminal session.

    Sets terminal to raw mode and forwards I/O between local stdin/stdout
    and the WebSocket connection.
    """
    stdin_fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(stdin_fd)

    # Send initial terminal size
    rows, cols = _get_terminal_size()
    await ws.send(protocol.resize_msg(rows, cols))

    # Handle SIGWINCH (terminal resize)
    loop = asyncio.get_running_loop()
    resize_event = asyncio.Event()

    def _on_sigwinch(signum, frame):
        resize_event.set()

    old_sigwinch = signal.signal(signal.SIGWINCH, _on_sigwinch)

    try:
        tty.setraw(stdin_fd)

        reader_task = asyncio.create_task(_ws_reader(ws))
        writer_task = asyncio.create_task(_stdin_writer(ws, stdin_fd))
        resize_task = asyncio.create_task(_resize_handler(ws, resize_event))

        done, pending = await asyncio.wait(
            [reader_task, writer_task, resize_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    finally:
        # Restore terminal
        termios.tcsetattr(stdin_fd, termios.TCSAFLUSH, old_settings)
        signal.signal(signal.SIGWINCH, old_sigwinch)
        print("\nDisconnected.")


async def _ws_reader(ws: websockets.ClientConnection) -> None:
    """Read from WebSocket and write to stdout."""
    try:
        async for message in ws:
            if isinstance(message, bytes):
                sys.stdout.buffer.write(message)
                sys.stdout.buffer.flush()
            elif isinstance(message, str):
                try:
                    msg = protocol.decode_control(message)
                    if msg.get("type") == protocol.MsgType.ERROR.value:
                        # Temporarily restore terminal to show error
                        sys.stderr.write(f"\r\n[Server error: {msg.get('message')}]\r\n")
                        sys.stderr.flush()
                except ValueError:
                    pass
    except websockets.ConnectionClosed:
        pass


async def _stdin_writer(
    ws: websockets.ClientConnection, stdin_fd: int
) -> None:
    """Read from stdin and write to WebSocket.

    Ctrl+] (0x1d) disconnects the session.
    """
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def _on_stdin_readable():
        try:
            data = os.read(stdin_fd, 4096)
            if data:
                queue.put_nowait(data)
            else:
                queue.put_nowait(None)
        except OSError:
            queue.put_nowait(None)

    loop.add_reader(stdin_fd, _on_stdin_readable)

    try:
        while True:
            data = await queue.get()
            if data is None:
                break
            # Check for Ctrl+] (GS, 0x1d) to disconnect
            if b"\x1d" in data:
                break
            await ws.send(data)
    except websockets.ConnectionClosed:
        pass
    finally:
        try:
            loop.remove_reader(stdin_fd)
        except (ValueError, OSError):
            pass


async def _resize_handler(
    ws: websockets.ClientConnection, resize_event: asyncio.Event
) -> None:
    """Watch for terminal resize events and send them to the server."""
    try:
        while True:
            await resize_event.wait()
            resize_event.clear()
            rows, cols = _get_terminal_size()
            await ws.send(protocol.resize_msg(rows, cols))
    except websockets.ConnectionClosed:
        pass


def _get_terminal_size() -> tuple[int, int]:
    """Get terminal size as (rows, cols)."""
    try:
        size = os.get_terminal_size()
        return size.lines, size.columns
    except OSError:
        return 24, 80
