from pathlib import Path
import tempfile
import types
import unittest
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch

from claude_protect.gui_model import dashboard, desktop_quote, extension_versions, install_command, launch_command, terminal_command


class PanelPolicyTests(unittest.TestCase):
    def test_extension_status_requires_registered_matching_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extension = root / "anthropic.claude-code-1.0.0"
            extension.mkdir()
            entry = {"identifier": {"id": "anthropic.claude-code"}, "version": "1.0.0", "relativeLocation": extension.name}
            (root / "extensions.json").write_text(json.dumps([entry]))
            self.assertEqual(extension_versions(root), ({}, ""))
            manifest = extension / "package.json"
            manifest.write_text(json.dumps({"publisher": "Anthropic", "name": "claude-code", "version": "1.0.0"}))
            self.assertEqual(extension_versions(root), ({"anthropic.claude-code": "1.0.0"}, ""))
            manifest.write_text(json.dumps({"publisher": "Anthropic", "name": "claude-code", "version": "2.0.0"}))
            self.assertEqual(extension_versions(root), ({}, ""))

    def test_bad_extension_registry_is_unknown_rather_than_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for content in ("invalid-json", "{}", '[{"identifier":null}]',
                            json.dumps([{"identifier": {"id": "anthropic.claude-code"}, "relativeLocation": "../outside"}])):
                with self.subTest(content=content):
                    (root / "extensions.json").write_text(content)
                    versions, error = extension_versions(root)
                    self.assertFalse(versions)
                    self.assertTrue(error)

    def test_host_panel_does_not_require_or_claim_own_session_isolation(self):
        view = dashboard({"kernel_ok": True, "session_isolated": False, "upstream_managed": True}, installed=True)
        self.assertEqual(view["mood"], "ready")
        self.assertNotIn("账号安全", view["title"])
        failed = dashboard({"kernel_ok": False, "session_isolated": True, "upstream_managed": True}, installed=True)
        self.assertEqual(failed["mood"], "alert")
        self.assertEqual(failed["tiles"][1].tone, "neutral")

    def test_untested_external_and_test_upstream_do_not_get_success_tone(self):
        for result in ({"upstream_managed": False}, {"upstream_managed": True, "upstream_test_only": True}):
            self.assertEqual(dashboard({"kernel_ok": True, **result})["tiles"][1].tone, "warn")

    def test_external_success_tone_requires_all_five_fresh_checks(self):
        import copy
        from claude_protect.diagnostics import timestamp
        from claude_protect.external_audit import ITEMS
        status = {"kernel_ok": True, "upstream_managed": False}
        result = {"checked_at": timestamp(), "status": "complete", "items": [
            {"id": key, "state": "pass"} for key in ITEMS]}
        tile = dashboard(status, upstream=result)["tiles"][1]
        self.assertEqual((tile.value, tile.tone), ("本次通过", "good"))
        for change in ("missing", "duplicate", "warn", "pending", "fix", "expired", "failed", "unready"):
            with self.subTest(change=change):
                changed = copy.deepcopy(result)
                state = dict(status)
                if change == "missing":
                    changed["items"].pop()
                elif change == "duplicate":
                    changed["items"][-1] = changed["items"][0]
                elif change in ("warn", "pending", "fix"):
                    changed["items"][0]["state"] = change
                elif change == "expired":
                    changed["checked_at"] = "2020-01-01T00:00:00+00:00"
                elif change == "failed":
                    changed["status"] = "failed"
                else:
                    state["kernel_ok"] = False
                self.assertNotEqual(dashboard(state, upstream=changed)["tiles"][1].tone, "good")

    def test_keyring_availability_does_not_claim_observed_browser_backend(self):
        view = dashboard(keyring={"available": True, "default_collection_unlocked": True})
        self.assertIn("待验收", view["tiles"][2].detail)
        self.assertEqual(dashboard(probe={"passed": False})["tiles"][3].tone, "bad")

    def test_install_validation_rejects_private_ip_hostname_plaintext_and_injected_user(self):
        user = types.SimpleNamespace(pw_uid=1000)
        with tempfile.TemporaryDirectory() as folder, patch("claude_protect.gui_model.pwd.getpwnam", return_value=user):
            root = Path(folder)
            (root / "scripts").mkdir()
            (root / "scripts/install.py").touch()
            for ip in ("127.0.0.1", "192.168.1.2", "proxy.example.com"):
                with self.subTest(ip=ip), self.assertRaises(ValueError):
                    install_command(root, user="tester", mode="managed", ip=ip, tls_name="proxy.example.com")
            with self.assertRaises(ValueError):
                install_command(root, user="tester;id", mode="external")
            with self.assertRaises(ValueError):
                install_command(root, user="tester", mode="external", local_port="1080;id")

    def test_authentication_is_interactive_and_not_a_password_argument(self):
        with tempfile.TemporaryDirectory() as folder, patch("claude_protect.gui_model.pwd.getpwnam", return_value=types.SimpleNamespace(pw_uid=1000)):
            root = Path(folder)
            (root / "scripts").mkdir()
            (root / "scripts/install.py").touch()
            argv = install_command(root, user="tester", mode="managed", ip="8.8.8.8", tls_name="proxy.example.com", auth=True)
            self.assertIn("--upstream-auth", argv)
            self.assertNotIn("--upstream-no-tls", argv)
            self.assertNotIn("--allow-test-upstream", argv)
            self.assertNotIn("password", " ".join(argv))

    def test_workspace_and_terminal_preserve_metacharacters_as_single_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "project ; $(id)"
            path.mkdir()
            argv = launch_command(str(path))
            self.assertEqual(argv[-1], str(path.resolve()))
            wrapped = terminal_command(argv, exists=lambda p: p.endswith("gnome-terminal"))
            self.assertEqual(wrapped[-len(argv):], argv)
            self.assertNotIn("sh", wrapped)

    def test_keyring_service_is_started_only_on_explicit_request(self):
        from claude_protect.cli import main
        with patch("sys.platform", "linux"), patch("claude_protect.keyring.verify", return_value={}) as verify, \
                patch("claude_protect.keyring.ensure", return_value={}) as ensure, redirect_stdout(io.StringIO()):
            main(["keyring-status", "--json"])
            verify.assert_called_once()
            ensure.assert_not_called()
            main(["keyring-status", "--json", "--start"])
            ensure.assert_called_once()

    def test_desktop_entry_escapes_both_string_and_exec_layers(self):
        quoted = desktop_quote('/tmp/a b/$cash/"quote"/100%/\\path')
        self.assertIn("%%", quoted)
        self.assertIn("\\\\$", quoted)
        self.assertIn("\\\\\\\\path", quoted)
        with self.assertRaises(ValueError):
            desktop_quote("/tmp/a\nExec=bad")

    def test_terminal_wrapper_preserves_failure_and_does_not_accept_non_sudo_commands(self):
        from claude_protect.admin_terminal import main
        with patch("claude_protect.admin_terminal.subprocess.run", return_value=types.SimpleNamespace(returncode=7)) as run, \
                patch("builtins.input", return_value=""), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["/usr/bin/sudo", "/usr/bin/python3", "/tmp/install.py"]), 7)
            run.assert_called_once()
            run.reset_mock()
            self.assertEqual(main(["/tmp/unexpected"]), 2)
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
