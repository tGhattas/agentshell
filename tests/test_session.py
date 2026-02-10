"""Tests for PTY session management."""

import time

from agentshell.session import PtySession


def test_spawn_and_read():
    session = PtySession("echo hello-test")
    session.spawn(rows=24, cols=80)
    time.sleep(0.5)

    output = b""
    for _ in range(10):
        try:
            data = session.read()
            if data:
                output += data
        except EOFError:
            break
        time.sleep(0.1)

    session.close()
    assert b"hello-test" in output


def test_resize():
    session = PtySession("sleep 2")
    session.spawn(rows=24, cols=80)
    # Should not raise
    session.resize(40, 120)
    session.close()


def test_write():
    session = PtySession("cat")
    session.spawn()
    session.write(b"ping\n")
    time.sleep(0.5)

    output = b""
    for _ in range(10):
        try:
            data = session.read()
            if data:
                output += data
        except EOFError:
            break
        time.sleep(0.1)

    session.close()
    assert b"ping" in output


def test_is_alive():
    session = PtySession("sleep 10")
    session.spawn()
    assert session.is_alive()
    session.close()
