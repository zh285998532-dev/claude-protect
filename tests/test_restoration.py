import json
import subprocess
import unittest
from unittest.mock import patch

from claude_protect.restoration import capture, verify_network_removed


class RestorationTests(unittest.TestCase):
    def query(self, commands, *, tables=None, service="ActiveState=inactive\nMainPID=0\n"):
        def run(argv):
            commands.append(argv)
            return json.dumps({"nftables": tables or []}) if argv[0].endswith("nft") else service
        return run

    def test_verification_is_read_only_and_leaves_unrelated_host_tables_alone(self):
        commands = []
        tables = [{"table": {"family": "inet", "name": "ufw"}}, {"table": {"family": "ip", "name": "docker"}}]
        result = verify_network_removed(query=self.query(commands, tables=tables), exists=lambda p: False, managed=True)
        self.assertTrue(result["upstream_table_removed"])
        self.assertFalse(result["host_network_reset"])
        self.assertEqual(len(commands), 5)
        for argv in commands:
            self.assertNotIn("flush", argv)
            self.assertNotIn("delete", argv)
            self.assertNotIn("restart", argv)

    def test_external_mode_does_not_require_a_nonexistent_upstream_unit(self):
        commands = []
        verify_network_removed(query=self.query(commands), exists=lambda p: False)
        self.assertFalse(any("claude-protect-upstream.service" in argv for argv in commands))

    def test_remaining_namespace_or_link_refuses_before_any_further_query(self):
        for remaining in ("/run/netns/claude-protect", "/sys/class/net/cp-host"):
            commands = []
            with self.assertRaises(RuntimeError):
                verify_network_removed(query=self.query(commands), exists=lambda p: p == remaining)
            self.assertEqual(commands, [])

    def test_unremoved_owned_table_or_running_service_is_not_reported_as_restored(self):
        commands = []
        with self.assertRaises(RuntimeError):
            verify_network_removed(query=self.query(commands, tables=[{"table": {"family": "inet", "name": "claude_protect_upstream"}}]), exists=lambda p: False)
        for service in ("ActiveState=active\nMainPID=123\n", "ActiveState=inactive\nMainPID=123\n", ""):
            with self.subTest(service=service), self.assertRaises(RuntimeError):
                verify_network_removed(query=self.query([], service=service), exists=lambda p: False)

    def test_invalid_or_failed_system_query_cannot_prove_absence(self):
        with self.assertRaises(RuntimeError):
            verify_network_removed(query=lambda argv: '{}', exists=lambda p: False)
        with patch("claude_protect.restoration.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            with self.assertRaises(RuntimeError):
                capture(["/usr/sbin/nft", "-j", "list", "tables"])


if __name__ == "__main__":
    unittest.main()
