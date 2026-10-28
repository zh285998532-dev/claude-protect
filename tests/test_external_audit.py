import http.server
import json
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

from claude_protect.config import Config
from claude_protect import external_audit as audit


class ExternalAuditTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(uid=1000, upstream_port=7897)

    def run_check(self, *, connection=None, dns=None, changed=False, controller=True, egress=True):
        snapshots = [({"mode": "global", "tun": True}, {}, "before"),
                     ({"mode": "global", "tun": True}, {}, "after" if changed else "before")]
        with patch.object(audit, "runtime", side_effect=snapshots if controller else OSError()), \
                patch.object(audit, "claude_connection", return_value=connection or
                             {"tls_verified": True, "chain_observed": True, "direct": False}), \
                patch.object(audit, "observe_dns", return_value=dns or {"source": "user_snapshot"}), \
                patch.object(audit, "dns_query", return_value={"ok": True, "error": None}), \
                patch.object(audit, "exit_sample", **({"return_value": {"ips": ["8.8.8.8"], "stable": True}}
                                                     if egress else {"side_effect": TimeoutError()})):
            return audit.check(self.config)

    def test_dns_configuration_pass_does_not_claim_packet_capture_or_fault_injection(self):
        result = self.run_check(dns={"source": "runtime", "respect_rules": True, "node_dns_configured": True})
        states = {item["id"]: item["state"] for item in result["items"]}
        self.assertEqual(states, {"controller": "pass", "route": "pass", "dns": "pass", "egress": "pass", "failover": "pending"})
        self.assertIn("只检查配置与解析", next(i for i in result["items"] if i["id"] == "dns")["detail"])
        self.assertFalse(result["upstream_managed"])

    def test_direct_and_unobserved_chain_are_not_passes(self):
        for connection, expected in (({"direct": True, "tls_verified": True, "chain_observed": True}, "fix"),
                                     ({"tls_verified": True}, "warn"), ({"tls_verified": False}, "warn")):
            result = self.run_check(connection=connection)
            self.assertEqual(next(i for i in result["items"] if i["id"] == "route")["state"], expected)

    def test_automatic_fallback_traversal_excludes_manual_direct_and_detects_automatic_direct(self):
        proxies = {"GLOBAL": {"type": "Selector", "now": "node", "all": ["node", "DIRECT"]},
                   "node": {"type": "AnyTLS"}, "DIRECT": {"type": "Direct"}}
        self.assertFalse(audit.automatic_direct(proxies, "GLOBAL"))
        for kind in ("Fallback", "URLTest", "LoadBalance"):
            proxies["GLOBAL"] = {"type": kind, "all": ["node", "DIRECT"]}
            self.assertTrue(audit.automatic_direct(proxies, "GLOBAL"))
        proxies["GLOBAL"] = {"type": "Selector", "now": "GLOBAL"}
        self.assertIsNone(audit.automatic_direct(proxies, "GLOBAL"))
        self.assertIsNone(audit.automatic_direct(proxies, "missing"))

    def test_dns_query_checks_dns_response_not_just_successful_http(self):
        for response, expected in (({"Status": 0, "Answer": [{"type": 1, "data": "8.8.8.8"}]}, True),
                                   ({"Status": 2, "Answer": []}, False), ({"Status": 0, "Answer": []}, False)):
            with patch.object(audit, "api_get", return_value=response):
                self.assertEqual(audit.dns_query("unused")["ok"], expected)

    def test_dns_timeout_and_core_http_error_are_distinct_from_dns_response_failure(self):
        for error, expected in ((TimeoutError(), "timeout"), (audit.ControllerHTTPError(500), "http_error"),
                                (audit.ControllerHTTPError(500, "timeout"), "core_timeout")):
            with patch.object(audit, "api_get", side_effect=error):
                result = audit.dns_query("unused")
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"], expected)

    def test_diagnostic_dns_targets_are_allowlisted(self):
        with patch.object(audit, "api_get") as request:
            with self.assertRaises(ValueError):
                audit.dns_query("unused", "private.example")
            request.assert_not_called()

    def test_runtime_dns_reader_requires_configured_users_explicit_admin_authorization(self):
        with patch.object(audit, "load_config", return_value=self.config), \
                patch.object(audit.os, "geteuid", return_value=1000), \
                patch.object(audit.os, "environ", {"SUDO_UID": "1000"}):
            with self.assertRaises(ValueError):
                audit.read_runtime_dns()

    def test_authorized_runtime_dns_reader_saves_only_fields_to_fixed_root_record(self):
        from types import SimpleNamespace
        import stat
        with patch.object(audit, "load_config", return_value=self.config), \
                patch.object(audit.os, "geteuid", return_value=0), \
                patch.object(audit.os, "environ", {"SUDO_UID": "1000"}), \
                patch.object(audit, "runtime", return_value=({}, {}, "signature")), \
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)), \
                patch.object(audit, "dns_settings", return_value={"respect_rules": False}) as read, \
                patch("claude_protect.config.atomic_json") as save, patch("builtins.print"):
            self.assertEqual(audit.read_runtime_dns(), 0)
            self.assertEqual(str(read.call_args.args[0]), "/var/lib/clash-verge-service/users/1000/runtime/config.yaml")
            self.assertEqual(save.call_args.args[0], audit.DNS_RECORD)
            self.assertEqual(save.call_args.args[1]["fields"], {"respect_rules": False})
        with patch.object(audit, "load_config", return_value=self.config), \
                patch.object(audit.os, "geteuid", return_value=0), \
                patch.object(audit.os, "environ", {"SUDO_UID": "1001"}):
            with self.assertRaises(ValueError):
                audit.read_runtime_dns()

    def test_unknown_controller_and_failed_exit_stay_explicitly_unverified(self):
        result = self.run_check(controller=False, egress=False, connection={"tls_verified": True})
        states = {i["id"]: i["state"] for i in result["items"]}
        self.assertEqual(states["controller"], "pending")
        self.assertEqual(states["dns"], "pending")
        self.assertEqual(states["egress"], "warn")
        self.assertNotIn("egress", result)

    def test_node_change_discards_successes_and_ip(self):
        result = self.run_check(changed=True)
        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(all(i["state"] == "pending" for i in result["items"]))
        self.assertNotIn("egress", result)
        self.assertNotIn("connection", result)

    def test_dns_parser_is_conservative_and_never_returns_names_or_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("secret: private-token\ndns:\n  respect-rules: true\n  proxy-server-nameserver:\n    - https://user:password@dns.example/query\nproxies: []\n")
            fields = audit.dns_settings(path)
            self.assertEqual(fields, {"respect_rules": True, "node_dns_configured": True})
            self.assertNotIn("password", json.dumps(fields))
            for content in ("dns: *alias\n", "dns:\n  <<: *defaults\n", "dns:\n  respect-rules: true\n  respect-rules: false\n"):
                path.write_text(content)
                self.assertEqual(audit.dns_settings(path), {})

    def test_runtime_port_mismatch_is_rejected_and_names_remain_private(self):
        with patch.object(audit, "api_get", side_effect=[{"mixed-port": 1234}, {"proxies": {}}]):
            with self.assertRaises(ValueError):
                audit.runtime("unused", self.config)
        proxies = {"GLOBAL": {"type": "Selector", "now": "private-node-name"},
                   "private-node-name": {"type": "AnyTLS"}}
        with patch.object(audit, "api_get", side_effect=[{"mixed-port": 7897}, {"proxies": proxies}]):
            snapshot, _, signature = audit.runtime("unused", self.config)
            self.assertEqual(snapshot["types"], ["Selector", "AnyTLS"])
            self.assertEqual(len(signature), 64)

    def test_exit_rejects_wrong_scope_policy_and_failed_subprocess(self):
        from types import SimpleNamespace
        sample = {"status": "complete", "target": audit.EGRESS_TARGET, "scope": "protected_namespace_to_ipify_only",
                  "policy_context": audit.policy_context(self.config), "observed_ips": ["8.8.8.8"], "stable_during_sample": True}
        for changes, code in (({"scope": "host"}, 0), ({"policy_context": "wrong"}, 0), ({}, 1)):
            with patch.object(audit.subprocess, "run", return_value=SimpleNamespace(returncode=code, stdout=json.dumps({**sample, **changes}))):
                with self.assertRaises(ValueError):
                    audit.exit_sample(self.config)

    def test_export_filters_private_payloads_and_masks_addresses(self):
        result = self.run_check()
        result.update(raw="private-token", dns={"source": "runtime", "secret": "private-token"})
        exported = audit.report(result)
        self.assertNotIn("private-token", json.dumps(exported))
        self.assertNotIn("8.8.8.8", json.dumps(exported))
        self.assertEqual(exported["observed_ips"], ["8.8.8.x"])

    def test_expired_success_is_not_exported_or_presented_as_current(self):
        result = self.run_check()
        result["checked_at"] = "2020-01-01T00:00:00+00:00"
        self.assertEqual(audit.summary(result)[0], "尚未检测")
        self.assertTrue(all(i["state"] == "pending" for i in audit.report(result)["items"]))

    def test_claude_chain_is_matched_to_this_test_source_port(self):
        from unittest.mock import MagicMock
        connection = MagicMock()
        connection.sock.getsockname.return_value = ("127.0.0.1", 32123)
        entries = [{"metadata": {"host": "claude.ai", "sourceIP": "127.0.0.1", "sourcePort": str(port)},
                    "chains": chain} for port, chain in ((32122, ["DIRECT"]), (32123, ["private-node", "GLOBAL"]))]
        with patch.object(audit.http.client, "HTTPSConnection", return_value=connection), \
                patch.object(audit, "api_get", return_value={"connections": entries}):
            result = audit.claude_connection(self.config, "unused", {"private-node": {"type": "AnyTLS"}, "GLOBAL": {"type": "Selector"}})
        self.assertTrue(result["chain_observed"])
        self.assertFalse(result["direct"])
        self.assertNotIn("private-node", json.dumps(result))

    def test_entrypoint_does_not_contact_proxy_when_kernel_is_unready(self):
        import io
        from contextlib import redirect_stdout
        with patch.object(audit, "load_config", return_value=self.config), \
                patch("claude_protect.cli.read_status", return_value={"kernel_ok": False}), \
                patch.object(audit, "check") as check, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 1)
            check.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["status"], "failed")

    def test_real_unix_transport_rejects_authenticated_malformed_and_oversized_replies(self):
        reply = {"status": 200, "body": b'{"mode":"global"}'}
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(reply["status"])
                self.end_headers()
                self.wfile.write(reply["body"])

            def log_message(self, *args):
                pass
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api.sock"
            server = socketserver.UnixStreamServer(str(path), Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(audit.api_get(path, "/configs"), {"mode": "global"})
                for code, body in ((401, b'password'), (200, b'[]'), (200, b'not JSON'), (200, b'x' * 200)):
                    reply.update(status=code, body=body)
                    with patch.object(audit, "LIMIT", 100), self.assertRaises(ValueError):
                        audit.api_get(path, "/configs")
            finally:
                server.shutdown()
                server.server_close()
                worker.join()


if __name__ == "__main__":
    unittest.main()
