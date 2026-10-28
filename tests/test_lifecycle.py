import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

from claude_protect.config import Config
from claude_protect import kernel


class LifecycleTests(unittest.TestCase):
    def collision_check(self, routes, links=None):
        def execute(args, **kwargs):
            data = (links or []) if "link" in args else routes
            return types.SimpleNamespace(stdout=json.dumps(data))
        with patch.object(kernel, "run", side_effect=execute):
            kernel.ensure_no_collision(Config(uid=1000))

    def test_tun_forwarding_supernets_do_not_claim_the_private_subnet(self):
        self.collision_check([
            {"dst": "0.0.0.0/1", "gateway": "198.18.0.2", "dev": "Mihomo", "table": 2022},
            {"dst": "128.0.0.0/1", "dev": "Mihomo", "table": 2022},
            {"dst": "198.18.0.0/30", "dev": "Mihomo", "scope": "link"},
        ], [{"ifname": "Mihomo", "linkinfo": {"info_kind": "tun"}}])

    def test_real_collisions_are_rejected_even_with_tun_enabled(self):
        links = [{"ifname": "Mihomo", "linkinfo": {"info_kind": "tun"}}]
        for route in (
            {"dst": "10.0.0.0/8", "dev": "eth0", "scope": "link"},
            {"dst": "10.254.253.0/30", "dev": "Mihomo", "table": 2022},
            {"dst": "10.254.253.2/32", "dev": "Mihomo", "table": 2022},
            {"dst": "10.254.253.0/24", "dev": "Mihomo", "scope": "link"},
            {"dst": "10.254.253.1", "dev": "Mihomo", "type": "local", "table": "local"},
            {"dst": "10.0.0.0/8", "dev": "Mihomo", "type": "blackhole"},
            {"dst": "10.0.0.0/8", "gateway": "192.168.1.1", "dev": "eth0"},
        ):
            with self.subTest(route=route), self.assertRaisesRegex(RuntimeError, "subnet conflicts"):
                self.collision_check([route], links)

    def test_return_route_requires_the_direct_project_link(self):
        config = Config(uid=1000)
        for route, expected in (
            ({"dev": "cp-host", "prefsrc": config.gateway}, True),
            ({"dev": "Mihomo", "gateway": "198.18.0.2"}, False),
            ({"dev": "cp-host", "gateway": "198.18.0.2"}, False),
            ({"dev": "cp-host", "prefsrc": "192.168.1.1"}, False),
        ):
            with self.subTest(route=route), patch.object(kernel, "run", return_value=types.SimpleNamespace(
                    stdout=json.dumps([route]))) as execute:
                self.assertEqual(kernel.host_route_ok(config), expected)
                execute.assert_called_once_with(["/usr/bin/nsenter", "--net=/proc/1/ns/net", "--",
                                                 kernel.TOOLS["ip"], "-j", "-4", "route", "get", config.client])

    def test_tun_interception_invalidates_an_otherwise_healthy_status(self):
        config = Config(uid=1000)
        observed = {"namespace_inode": 123, "rules_sha256": "policy", "routes": [
            {"dst": config.subnet, "dev": "cp0", "scope": "link"}], "routes6": [],
            "addresses": [{"local": config.client, "prefixlen": 30, "family": "inet"}]}
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            state.write_text(json.dumps({**observed, "config": config.to_dict()}))
            with patch.object(kernel, "STATE", state), patch.object(kernel, "trusted_file"), \
                    patch.object(kernel, "observe", return_value=observed), \
                    patch.object(kernel, "host_route_ok", return_value=False):
                result = kernel.status(config)
        self.assertFalse(result["kernel_ok"])
        self.assertFalse(result["checks"]["host_return_route"])

    def test_tun_interception_during_setup_rolls_back_new_namespace(self):
        config = Config(uid=1000)
        commands = []

        def execute(args, **kwargs):
            commands.append(args)
            return types.SimpleNamespace(returncode=1 if args == [
                kernel.TOOLS["ip"], "link", "show", kernel.HOST_LINK] else 0, stdout="")

        namespace = MagicMock()
        namespace.exists.return_value = False
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(kernel, "Path", return_value=namespace), \
                patch.object(kernel, "STATE", Path(folder) / "state.json"), \
                patch.object(kernel, "STATE_DIR", Path(folder)), \
                patch.object(kernel, "ensure_no_collision"), patch.object(kernel, "observe", return_value={}), \
                patch.object(kernel, "topology_ok", return_value=True), \
                patch.object(kernel, "host_route_ok", return_value=False), \
                patch.object(kernel, "run", side_effect=execute):
            with self.assertRaisesRegex(RuntimeError, "return route is intercepted"):
                kernel.setup(config)
            self.assertFalse(kernel.STATE.exists())
        self.assertEqual(commands[-2:], [[kernel.TOOLS["ip"], "link", "delete", kernel.HOST_LINK],
                                         [kernel.TOOLS["ip"], "netns", "delete", kernel.NAMESPACE]])

    def test_setup_never_overwrites_an_existing_unverified_namespace(self):
        namespace = MagicMock()
        namespace.exists.return_value = True
        with patch.object(kernel, "Path", return_value=namespace), \
                patch.object(kernel, "status", return_value={"kernel_ok": False}), \
                patch.object(kernel, "run") as execute:
            with self.assertRaises(RuntimeError):
                kernel.setup(Config(uid=1000))
            execute.assert_not_called()

    def test_firewall_install_failure_rolls_back_new_links_before_any_application_launch(self):
        commands = []

        def execute(args, **kwargs):
            commands.append(args)
            if args == [kernel.TOOLS["ip"], "link", "show", kernel.HOST_LINK]:
                return types.SimpleNamespace(returncode=1, stdout="")
            if args[-3:] == [kernel.TOOLS["nft"], "-f", "-"]:
                raise RuntimeError("simulated firewall failure")
            return types.SimpleNamespace(returncode=0, stdout="")

        namespace = MagicMock()
        namespace.exists.return_value = False
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(kernel, "Path", return_value=namespace), \
                patch.object(kernel, "STATE", Path(folder) / "state.json"), \
                patch.object(kernel, "STATE_DIR", Path(folder)), \
                patch.object(kernel, "ensure_no_collision"), \
                patch.object(kernel, "run", side_effect=execute):
            with self.assertRaisesRegex(RuntimeError, "firewall failure"):
                kernel.setup(Config(uid=1000))
        self.assertEqual(commands[-2:], [[kernel.TOOLS["ip"], "link", "delete", kernel.HOST_LINK],
                                         [kernel.TOOLS["ip"], "netns", "delete", kernel.NAMESPACE]])

    def test_active_process_prevents_namespace_teardown(self):
        namespace = MagicMock()
        namespace.exists.return_value = True
        namespace.stat.return_value = types.SimpleNamespace(st_ino=123)
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            state.write_text(json.dumps({"namespace_inode": 123}))
            with patch.object(kernel, "Path", return_value=namespace), \
                    patch.object(kernel, "STATE", state), patch.object(kernel, "trusted_file"), \
                    patch.object(kernel, "run", return_value=types.SimpleNamespace(stdout="4321\n")) as execute:
                with self.assertRaisesRegex(RuntimeError, "still running"):
                    kernel.teardown(Config(uid=1000))
                execute.assert_called_once_with([kernel.TOOLS["ip"], "netns", "pids", kernel.NAMESPACE])


if __name__ == "__main__":
    unittest.main()
