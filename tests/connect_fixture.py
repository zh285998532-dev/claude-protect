"""Local-only acceptance fixture: CONNECT to example.com:443, no credentials."""
import asyncio
import sys


async def connection(reader, writer):
    remote = None
    tasks = []
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        if not request.startswith(b"CONNECT example.com:443 HTTP/1."):
            return
        upstream, remote = await asyncio.wait_for(asyncio.open_connection("example.com", 443), 10)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def copy(source, destination):
            while block := await source.read(65536):
                destination.write(block)
                await destination.drain()

        tasks = [asyncio.create_task(copy(reader, remote)), asyncio.create_task(copy(upstream, writer))]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (writer, remote):
            if stream:
                stream.close()
                try:
                    await stream.wait_closed()
                except OSError:
                    pass


async def main():
    server = await asyncio.start_server(connection, "127.0.0.1", int(sys.argv[1]))
    print("ready", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
