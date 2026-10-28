import io
import json
import os
from pathlib import Path
import signal
import ssl
import tempfile
import time
import unittest
import types
from unittest.mock import MagicMock, patch

from claude_protect.config import Config
from claude_protect.diagnostics import (EGRESS_TARGET, History, audit_environment,
                                         diagnostic_report, save_report)
from claude_protect.egress import deadline, observe, sample
from claude_protect.helper import application_command


def observation(ip="8.8.8.8", context="a" * 64):
    return {"status": "complete", "target": EGRESS_TARGET, "checked_at": "2026-10-25T08:00:00+00:00",
            "policy_context": context, "observed_ips": [ip], "stable_during_sample": True}


class DiagnosticsTests(unittest.TestCase):
    def test_audit_detects_configuration_conflicts_without_returning_credentials_or_urls(self):
        environment = {"HTTPS_PROXY": "https://alice:proxysecret@proxy.invalid:443",
                       "https_proxy": "http://second.invalid:7890", "NO_PROXY": "*,secret-in-bypass",
                       "ANTHROPIC_API_KEY": "sk-ant-secret", "ANTHROPIC_BASE_URL": "https://provider.invalid/?key=endpointsecret",
                       "NODE_TLS_REJECT_UNAUTHORIZED": "0", "LANG": "zh_CN.UTF-8"}
        result = audit_environment(environment)
        ids = {item["id"] for item in result["findings"]}
        self.assertTrue({"proxy_case_conflict", "proxy_bypass", "api_key_present", "provider_override", "tls_verification_disabled"} <= ids)
        encoded = json.dumps(result)
        for value in ("alice", "proxysecret", "proxy.invalid", "second.invalid", "secret-in-bypass", "sk-ant-secret", "endpointsecret"):
            self.assertNotIn(value, encoded)
        self.assertEqual(result["scope"], "current_process_environment_only")
        self.assertIn("running_claude_environment", result["not_checked"])

    def test_language_is_information_not_a_synthetic_ban_score(self):
        result = audit_environment({"LANG": "zh_CN.UTF-8", "NO_PROXY": "localhost,127.0.0.1,::1"})
        self.assertEqual(result["environment"]["locale"], "zh_CN.UTF-8")
        self.assertTrue(all(item["level"] == "info" for item in result["findings"]))
        self.assertNotIn("score", result)
        malformed = audit_environment({"HTTPS_PROXY": "https://proxy.invalid:0", "HTTP_PROXY": "bad[URL"})
        self.assertIn("malformed_proxy", {item["id"] for item in malformed["findings"]})

    def test_egress_cannot_open_any_connection_outside_verified_isolation(self):
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": False}), \
                patch("claude_protect.egress.http.client.HTTPSConnection") as connection:
            with self.assertRaises(RuntimeError):
                observe(Config(uid=1000))
            connection.assert_not_called()

    def test_observation_uses_only_literal_relay_and_verified_tls_to_fixed_target(self):
        config = Config(uid=1000)
        with patch("claude_protect.egress.http.client.HTTPSConnection") as factory:
            connection = factory.return_value
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = b'{"ip":"8.8.8.8","secret":"ignored"}'
            result = sample(config)
        self.assertTrue(result["ok"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(factory.call_args.args, (config.gateway, config.relay_port))
        context = factory.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        connection.set_tunnel.assert_called_once_with("api.ipify.org", 443)
        self.assertEqual(connection.request.call_args.args, ("GET", "/?format=json"))
        connection.close.assert_called_once()

    def test_redirects_private_ips_oversized_and_non_json_responses_do_not_pass(self):
        for status, body in ((302, b'{"ip":"8.8.8.8"}'), (200, b'{"ip":"192.168.1.1"}'),
                             (200, b"x" * 4097), (200, b"<html>error</html>")):
            with self.subTest(status=status, body=body[:40]), patch("claude_protect.egress.http.client.HTTPSConnection") as factory:
                connection = factory.return_value
                connection.getresponse.return_value.status = status
                connection.getresponse.return_value.read.return_value = body
                result = sample(Config(uid=1000))
                self.assertFalse(result["ok"])
                self.assertNotIn("ip", result)
                self.assertEqual(connection.request.call_count, 1)

    def test_partial_sampling_and_rotation_do_not_claim_anthropic_exit_or_account_safety(self):
        for samples, expected, stable in (([{"ok": True, "ip": "8.8.8.8"}, {"ok": False}], "partial", None),
                                          ([{"ok": True, "ip": "8.8.8.8"}, {"ok": True, "ip": "1.1.1.1"}], "complete", False)):
            with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                    patch("claude_protect.egress.sample", side_effect=samples):
                result = observe(Config(uid=1000))
            self.assertEqual(result["status"], expected)
            self.assertIs(result["stable_during_sample"], stable)
            self.assertEqual(result["anthropic_egress"], "not_observed")
            self.assertEqual(result["account_safety"], "not_assessed")

    def test_policy_change_aborts_sampling_and_absolute_deadline_restores_signal_handler(self):
        with patch("claude_protect.cli.read_status", side_effect=[{"session_isolated": True}, {"session_isolated": False}]), \
                patch("claude_protect.egress.sample", return_value={"ok": True, "ip": "8.8.8.8"}) as request:
            with self.assertRaises(RuntimeError):
                observe(Config(uid=1000))
            self.assertEqual(request.call_count, 1)
        original = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with deadline(.02):
                time.sleep(.1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)

    def test_egress_helper_exec_is_fixed_and_takes_no_user_endpoint(self):
        user = MagicMock(pw_dir="/home/tester")
        self.assertEqual(application_command(Config(uid=1000), user, "egress"),
                         ["/usr/bin/python3", "-I", "/usr/local/libexec/claude-protect-probe", "--egress"])

    def test_history_compares_only_same_policy_and_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            history = History(Path(folder) / "private/history.json")
            self.assertIsNone(history.record(observation())["changed_since_previous"])
            self.assertTrue(history.record(observation("1.1.1.1"))["changed_since_previous"])
            self.assertIsNone(history.record(observation("9.9.9.9", "b" * 64))["changed_since_previous"])
            for _ in range(31):
                history.record(observation())
            self.assertEqual(len(history.read()), 30)
            self.assertEqual(history.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(history.path.parent.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(ValueError):
                history.record({**observation(), "status": "partial"})
            history.clear()
            self.assertEqual(history.read(), [])

    def test_history_refuses_symlinks_hardlinks_and_publicly_readable_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            outside = root / "outside"
            outside.write_text("do not touch")
            path = root / "history.json"
            history = History(path)
            path.symlink_to(outside)
            with self.assertRaises((OSError, ValueError)):
                history.record(observation())
            path.unlink()
            os.link(outside, path)
            with self.assertRaises(ValueError):
                history.read()
            path.unlink()
            history.record(observation())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                history.read()
            self.assertEqual(outside.read_text(), "do not touch")

    def test_report_exports_allowlisted_fields_and_masked_ips_only(self):
        secret = "neverexportthissecret"
        report = diagnostic_report(status={"uid": 1000, "proxy_url": secret, "checks": {secret: True, "firewall": True}},
                                   probe={"passed": True, "error": secret, "checks": {secret: False}},
                                   audit={"findings": [{"id": secret, "message": secret}, {"id": "proxy_bypass"}], "env": secret},
                                   egress={**observation(), "samples": [{"ok": True, "ip": "8.8.8.8", "error": secret, "total_ms": 13}]})
        encoded = json.dumps(report)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("8.8.8.8", encoded)
        self.assertIn("8.8.8.x", encoded)
        self.assertEqual(report["environment_audit"]["finding_ids"], ["proxy_bypass"])
        self.assertEqual(report["not_tested"], ["browser_webrtc", "authoritative_dns_leak_test", "dns_packet_capture", "claude_streaming_connection"])
        self.assertEqual(diagnostic_report()["probe"]["state"], "not_tested")

    def test_report_file_is_private_and_cannot_truncate_a_linked_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "report.json"
            save_report(target, diagnostic_report())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            linked = root / "linked.json"
            os.link(target, linked)
            original = target.read_bytes()
            with self.assertRaises(ValueError):
                save_report(linked, {})
            self.assertEqual(target.read_bytes(), original)

    def test_network_probe_rechecks_isolation_after_positive_control(self):
        from claude_protect.probe import probe
        with patch("claude_protect.cli.read_status", side_effect=[{"session_isolated": True}, {"session_isolated": False}]), \
                patch("claude_protect.probe.os.stat", return_value=types.SimpleNamespace(st_ino=123)), \
                patch("claude_protect.probe.denied", return_value=True), \
                patch("claude_protect.probe.socket.getaddrinfo", side_effect=OSError()), \
                patch("claude_protect.probe.ssl.create_default_context"), \
                patch("claude_protect.probe.http.client.HTTPSConnection") as factory:
            factory.return_value.getresponse.return_value.status = 200
            result = probe(Config(uid=1000))
            self.assertFalse(result["passed"])
            self.assertTrue(result["checks"]["proxy_tls_verified"])
            self.assertFalse(result["checks"]["runtime_isolated_after"])

    def test_new_diagnostic_modes_cannot_accept_arbitrary_destinations(self):
        from claude_protect.cli import main
        from claude_protect import session
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()), patch("claude_protect.cli.launch") as launch:
            for mode in ("egress", "stream-check"):
                with self.assertRaises(SystemExit):
                    main([mode, "https://unexpected.invalid/"])
            launch.assert_not_called()
        with patch("sys.argv", ["session", "egress", "https://unexpected.invalid/"]), \
                patch("claude_protect.config.load_config") as load:
            with self.assertRaises(ValueError):
                session.main()
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
