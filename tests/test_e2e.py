"""End-to-end tests for the server and client protocol."""

import asyncio
import tempfile
from pathlib import Path

import pytest
import websockets

from agentshell.auth import hash_password
from agentshell.config import Config
from agentshell.protocol import auth_request, decode_control, resize_msg
from agentshell.server import AgentShellServer
from agentshell.tls import create_client_ssl_context, generate_self_signed_cert


@pytest.fixture()
def server_env():
    """Set up a temporary server environment."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cert = Config.cert_path(tmp)
        key = Config.key_path(tmp)
        fp = generate_self_signed_cert(cert, key)

        config = Config()
        config.server.host = "127.0.0.1"
        config.server.port = 18920
        config.server.password_hash = hash_password("e2e-test-pass")
        config.server.shell_command = "echo e2e-output && sleep 1"
        config.server.cert_fingerprint = fp
        config.save(tmp)

        yield config, tmp


@pytest.mark.asyncio
async def test_auth_and_pty_output(server_env):
    config, tmp = server_env
    server = AgentShellServer(config, tmp)
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(1)

    ssl_ctx = create_client_ssl_context()
    try:
        async with websockets.connect(
            "wss://127.0.0.1:18920",
            ssl=ssl_ctx,
            server_hostname="localhost",
        ) as ws:
            await ws.send(auth_request("e2e-test-pass"))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = decode_control(resp)
            assert msg["ok"]

            await ws.send(resize_msg(30, 100))

            output = b""
            try:
                while True:
                    data = await asyncio.wait_for(ws.recv(), timeout=3)
                    if isinstance(data, bytes):
                        output += data
            except (asyncio.TimeoutError, websockets.ConnectionClosed):
                pass

            assert b"e2e-output" in output
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_bad_password_rejected(server_env):
    config, tmp = server_env
    server = AgentShellServer(config, tmp)
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(1)

    ssl_ctx = create_client_ssl_context()
    try:
        async with websockets.connect(
            "wss://127.0.0.1:18920",
            ssl=ssl_ctx,
            server_hostname="localhost",
        ) as ws:
            await ws.send(auth_request("wrong-password"))
            resp = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = decode_control(resp)
            assert not msg["ok"]
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
