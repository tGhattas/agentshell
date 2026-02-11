"""PTY session management — spawns and manages terminal sessions."""

import asyncio
import fcntl
import os
import pty
import signal
import struct
import termios
from typing import Any, Callable, Coroutine


class PtySession:
    """Manages a single PTY session running a shell command."""

    def __init__(self, command: str, env: dict[str, str] | None = None):
        self.command = command
        self.env = env or {}
        self.master_fd: int | None = None
        self.child_pid: int | None = None
        self._closed = False

    def spawn(self, rows: int = 24, cols: int = 80) -> None:
        """Spawn the child process in a new PTY."""
        child_pid, master_fd = pty.openpty()

        # Actually, pty.openpty returns (master_fd, slave_fd).
        # We need to fork properly. Let's use pty.fork() instead.
        # Undo the openpty.
        os.close(child_pid)
        os.close(master_fd)

        pid, fd = pty.fork()

        if pid == 0:
            # Child process
            env = os.environ.copy()
            env.update(self.env)
            env["TERM"] = env.get("TERM", "xterm-256color")
            env["COLUMNS"] = str(cols)
            env["LINES"] = str(rows)

            # Split command for exec
            import shlex
            args = shlex.split(self.command)
            os.execvpe(args[0], args, env)
            # If exec fails, we never reach here, but just in case:
            os._exit(1)
        else:
            # Parent process
            self.child_pid = pid
            self.master_fd = fd

            # Set initial terminal size
            self.resize(rows, cols)

            # Make reads non-blocking
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def resize(self, rows: int, cols: int) -> None:
        """Resize the PTY terminal."""
        if self.master_fd is not None:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            # Notify child of resize
            if self.child_pid is not None:
                try:
                    os.kill(self.child_pid, signal.SIGWINCH)
                except ProcessLookupError:
                    pass

    def write(self, data: bytes) -> None:
        """Write data to the PTY (sends input to the child process)."""
        if self.master_fd is not None and not self._closed:
            os.write(self.master_fd, data)

    def read(self, size: int = 4096) -> bytes:
        """Read available data from the PTY (output from child process).

        Returns empty bytes if no data is available (non-blocking).
        Raises EOFError if the child has exited.
        """
        if self.master_fd is None or self._closed:
            raise EOFError("Session closed")
        try:
            return os.read(self.master_fd, size)
        except BlockingIOError:
            return b""
        except OSError:
            raise EOFError("PTY read error — child likely exited")

    def is_alive(self) -> bool:
        """Check if the child process is still running."""
        if self.child_pid is None:
            return False
        try:
            pid, status = os.waitpid(self.child_pid, os.WNOHANG)
            return pid == 0
        except ChildProcessError:
            return False

    def close(self) -> None:
        """Terminate the session and clean up."""
        if self._closed:
            return
        self._closed = True

        if self.child_pid is not None:
            try:
                os.kill(self.child_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Give the child a moment then force kill
            try:
                pid, _ = os.waitpid(self.child_pid, os.WNOHANG)
                if pid == 0:
                    os.kill(self.child_pid, signal.SIGKILL)
                    os.waitpid(self.child_pid, 0)
            except (ChildProcessError, ProcessLookupError):
                pass

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass

    def __del__(self) -> None:
        self.close()


async def pty_read_loop(
    session: PtySession,
    callback: Callable[[bytes], Coroutine[Any, Any, None]],
    loop: asyncio.AbstractEventLoop | None = None,
) -> None:
    """Async loop that reads from the PTY and calls callback with data.

    Uses asyncio's add_reader for efficient event-driven I/O.
    """
    if session.master_fd is None:
        return

    loop = loop or asyncio.get_running_loop()
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def _on_readable() -> None:
        try:
            data = os.read(session.master_fd, 16384)
            if data:
                queue.put_nowait(data)
            else:
                queue.put_nowait(None)
        except OSError:
            queue.put_nowait(None)

    loop.add_reader(session.master_fd, _on_readable)
    try:
        while True:
            data = await queue.get()
            if data is None:
                break
            await callback(data)
    finally:
        try:
            loop.remove_reader(session.master_fd)
        except (ValueError, OSError):
            pass
