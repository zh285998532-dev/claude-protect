import asyncio
import socket
import unittest

from claude_protect.relay import Relay


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.connections = []

    async def asyncTearDown(self):
        for writer in self.connections:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        for server in self.servers:
            server.close()
            await server.wait_closed()
        await asyncio.sleep(0.05)

    async def server(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()

    async def connect(self, address):
        reader, writer = await asyncio.open_connection(*address)
        self.connections.append(writer)
        return reader, writer

    async def test_connect_authority_and_bytes_pass_through_without_dns_or_tls_rewrite(self):
        requests = []

        async def upstream(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            requests.append(request)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            body = await reader.readexactly(6)
            writer.write(body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream_address = await self.server(upstream)
        relay = Relay(upstream_address, "127.0.0.1", idle_timeout=1)
        address = await self.server(relay.connection)
        reader, writer = await self.connect(address)
        request = b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n"
        writer.write(request)
        await writer.drain()
        self.assertIn(b"200", await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
        writer.write(b"\x16\x03\x03abc")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 2), b"\x16\x03\x03abc")
        self.assertEqual(requests, [request])

    async def test_failed_upstream_closes_client_without_any_direct_fallback(self):
        temporary = socket.socket()
        temporary.bind(("127.0.0.1", 0))
        unavailable = temporary.getsockname()
        temporary.close()
        relay = Relay(unavailable, "127.0.0.1", idle_timeout=1)
        address = await self.server(relay.connection)
        reader, _ = await self.connect(address)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(relay.active, 0)

    async def test_other_sources_are_rejected_before_upstream_connection(self):
        called = []

        async def upstream(reader, writer):
            called.append(True)
            writer.close()

        upstream_address = await self.server(upstream)
        relay = Relay(upstream_address, "192.0.2.1", idle_timeout=1)
        reader, _ = await self.connect(await self.server(relay.connection))
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(called, [])

    async def test_half_close_preserves_upstream_response(self):
        async def upstream(reader, writer):
            data = await reader.read()
            writer.write(data.upper())
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        relay = Relay(await self.server(upstream), "127.0.0.1", idle_timeout=1)
        reader, writer = await self.connect(await self.server(relay.connection))
        writer.write(b"last message")
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"LAST MESSAGE")


if __name__ == "__main__":
    unittest.main()
