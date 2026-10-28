import types
import os
import unittest
from unittest.mock import patch

from claude_protect.browser import main
from claude_protect.config import Config


class BrowserBoundaryTests(unittest.TestCase):
    def test_browser_cannot_start_before_runtime_isolation_is_verified(self):
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": False}), \
                patch("claude_protect.browser.os.execve") as execute:
            with self.assertRaisesRegex(RuntimeError, "verified protected environment"):
                main(["https://claude.ai/"])
            execute.assert_not_called()

    def test_official_callback_targets_the_dedicated_code_profile(self):
        user = types.SimpleNamespace(pw_dir="/home/tester", pw_uid=1000, pw_gid=1000, pw_name="tester")
        url = "vscode://anthropic.claude-code/callback?code=opaque&state=opaque"
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                patch("claude_protect.keyring.verify", return_value={"available": True}), \
                patch("claude_protect.config.load_config", return_value=Config(uid=1000)), \
                patch("claude_protect.browser.pwd.getpwuid", return_value=user), \
                patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "NODE_TLS_REJECT_UNAUTHORIZED": "0"}), \
                patch("claude_protect.browser.os.execve") as execute:
            main([url])
        executable, args, environment = execute.call_args.args
        self.assertEqual(executable, "/usr/bin/code")
        self.assertEqual(args[args.index("--user-data-dir") + 1], "/home/tester/.local/share/claude-protect/code")
        self.assertEqual(args[-2:], ["--open-url", url])
        self.assertEqual(environment["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1000/claude-protect-keyring/bus")
        self.assertNotIn("NODE_TLS_REJECT_UNAUTHORIZED", environment)

    def test_browser_cannot_start_when_keyring_preflight_fails(self):
        with patch("claude_protect.cli.read_status", return_value={"session_isolated": True}), \
                patch("claude_protect.keyring.verify", side_effect=RuntimeError("locked")), \
                patch("claude_protect.browser.os.execve") as execute:
            with self.assertRaisesRegex(RuntimeError, "locked"):
                main(["https://claude.ai/"])
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
