import asyncio
import socket
import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from claude_protect.config import Config
from claude_protect.upstream import UpstreamProxy, authority, request_bytes
from claude_protect.upstream_policy import policy, setup


def configuration(port=443, **overrides):
    fields = dict(uid=1000, proxy_uid=999, proxy_mode="managed", upstream_ip="127.0.0.1",
                  upstream_remote_port=port, upstream_tls=False, upstream_test_only=True)
    fields.update(overrides)
    return Config(**fields)


class UpstreamPolicyTests(unittest.TestCase):
    def test_production_rejects_private_plaintext_and_hostname_endpoints(self):
        for changes in ({"upstream_test_only": False}, {"upstream_ip": "proxy.example.com"},
                        {"upstream_ip": "1.1.1.1", "upstream_test_only": False, "upstream_tls": False},
                        {"proxy_uid": 1000}, {"proxy_uid": 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                configuration(**changes)

    def test_authority_rejects_header_and_url_smuggling(self):
        for first_line in (b"GET https://example.com HTTP/1.1", b"CONNECT user:pass@example.com:443 HTTP/1.1",
                           b"CONNECT example.com:53 HTTP/1.1", b"CONNECT example.com:443\r\nBad HTTP/1.1",
                           b"CONNECT example.com/path:443 HTTP/1.1"):
            with self.subTest(line=first_line), self.assertRaises(ValueError):
                authority(first_line)
        self.assertEqual(authority(b"CONNECT api.anthropic.com:443 HTTP/1.1"), "api.anthropic.com:443")

    def test_credentials_cannot_inject_headers(self):
        with self.assertRaises(ValueError):
            request_bytes("example.com:443", "user:other", "secret")
        with self.assertRaises(ValueError):
            request_bytes("example.com:443", "user", "password\r\nInjected: true")

    def test_host_policy_is_scoped_to_service_uid_and_one_endpoint(self):
        config = configuration()
        rules = policy(config)
        self.assertIn("policy accept", rules)
        self.assertIn(f"meta skuid {config.proxy_uid} ip daddr {config.upstream_ip} tcp dport {config.upstream_remote_port}", rules)
        self.assertIn(f"meta skuid {config.proxy_uid} counter drop", rules)
        self.assertNotIn("udp dport 53", rules)
        self.assertNotIn("flush ruleset", rules)

    def test_existing_unowned_upstream_table_is_never_overwritten(self):
        with patch("claude_protect.upstream_policy.observe", return_value="existing"), patch("claude_protect.kernel.run") as execute:
            with self.assertRaises(RuntimeError):
                setup(configuration())
            execute.assert_not_called()

    def test_upstream_filter_tampering_invalidates_kernel_status(self):
        from claude_protect import kernel
        config = configuration()
        observed = {"namespace_inode": 123, "rules_sha256": "app-policy", "routes": [
            {"dst": config.subnet, "dev": "cp0", "scope": "link"}], "routes6": [],
            "addresses": [{"local": config.client, "prefixlen": 30, "family": "inet"}]}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({**observed, "config": config.to_dict(), "upstream_rules_sha256": "expected"}))
            with patch.object(kernel, "STATE", state), patch.object(kernel, "trusted_file"), \
                    patch.object(kernel, "observe", return_value=observed), \
                    patch.object(kernel, "host_route_ok", return_value=True), \
                    patch("claude_protect.upstream_policy.observe", return_value="modified"):
                result = kernel.status(config)
        self.assertFalse(result["checks"]["upstream_egress"])
        self.assertFalse(result["kernel_ok"])


class UpstreamConnectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers, self.writers = [], []

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        for server in self.servers:
            server.close()
            await server.wait_closed()
        await asyncio.sleep(0.05)

    async def listen(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def client(self, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def test_target_stays_a_domain_and_client_auth_headers_are_not_forwarded(self):
        requests = []

        async def remote(reader, writer):
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 Connection Established\r\nUpstream-Private: hidden\r\n\r\n")
            await writer.drain()
            body = await reader.readexactly(6)
            writer.write(body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        proxy = UpstreamProxy(configuration(await self.listen(remote)), username="provider-user", password="provider-secret", idle_timeout=1)
        reader, writer = await self.client(await self.listen(proxy.connection))
        writer.write(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nProxy-Authorization: client-secret\r\nX-Leak: private\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
        self.assertNotIn(b"Upstream-Private", reply)
        writer.write(b"\x16\x03\x03abc")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 2), b"\x16\x03\x03abc")
        self.assertTrue(requests[0].startswith(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"))
        self.assertIn(b"Proxy-Authorization: Basic ", requests[0])
        self.assertNotIn(b"client-secret", requests[0])
        self.assertNotIn(b"X-Leak", requests[0])

    async def test_refused_upstream_never_falls_back_to_target(self):
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        proxy = UpstreamProxy(configuration(port), idle_timeout=1)
        reader, writer = await self.client(await self.listen(proxy.connection))
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 2)
        self.assertIn(b"502", reply)
        self.assertNotIn(b"200 Connection", reply)

    async def test_upstream_auth_failure_is_not_reported_as_a_live_tunnel(self):
        async def remote(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nX-Secret: hidden\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        proxy = UpstreamProxy(configuration(await self.listen(remote)), idle_timeout=1)
        reader, writer = await self.client(await self.listen(proxy.connection))
        writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(), 2)
        self.assertIn(b"502", reply)
        self.assertNotIn(b"hidden", reply)

    async def test_tls_name_does_not_replace_the_literal_connection_address(self):
        proxy = UpstreamProxy(configuration(upstream_tls=True, upstream_tls_name="proxy.example.com"))
        with patch("claude_protect.upstream.asyncio.open_connection", new_callable=AsyncMock, return_value=(None, None)) as connect:
            await proxy.connect_upstream()
        self.assertEqual(connect.call_args.args, ("127.0.0.1", 443))
        self.assertEqual(connect.call_args.kwargs["server_hostname"], "proxy.example.com")
        self.assertTrue(connect.call_args.kwargs["ssl"].check_hostname)
