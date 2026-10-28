"""Read-only privileged status socket, usable after NoNewPrivileges is enabled."""
import asyncio
import json
import os
import signal
import socket
import struct

from .config import STATE_DIR, load_config
from .kernel import status

STATUS_SOCKET = STATE_DIR / "status.sock"


async def serve():
    config = load_config()
    if STATUS_SOCKET.exists():
        STATUS_SOCKET.unlink()

    async def reply(reader, writer):
        try:
            uid = struct.unpack("3i", writer.get_extra_info("socket").getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
            if uid not in (0, config.uid):
                return
            try:
                result = status(config)
            except (RuntimeError, ValueError, OSError) as error:
                result = {"schema": 1, "kernel_ok": False, "error": str(error)}
            writer.write(json.dumps(result).encode() + b"\n")
            await asyncio.wait_for(writer.drain(), 3)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    server = await asyncio.start_unix_server(reply, str(STATUS_SOCKET))
    os.chmod(STATUS_SOCKET, 0o666)  # SO_PEERCRED restricts access; the directory is root-owned.
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    try:
        async with server:
            await stop.wait()
    finally:
        STATUS_SOCKET.unlink(missing_ok=True)


def main():
    asyncio.run(serve())
