from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from claude_protect.keyring import proxy_arguments, verify
from claude_protect.config import Config
from claude_protect.helper import app_environment
import types


class KeyringTests(unittest.TestCase):
    def test_dbus_rules_allow_only_secret_service_not_host_network_services(self):
        args = proxy_arguments("/run/user/1000")
        self.assertIn("--filter", args)
        self.assertFalse(any(arg.startswith("--talk=") for arg in args))
        for option in args:
            if option.startswith(("--call=", "--broadcast=")):
                self.assertTrue(option.startswith(("--call=org.freedesktop.secrets=", "--broadcast=org.freedesktop.secrets=")))
        self.assertNotIn("org.freedesktop.resolve1", " ".join(args))
        self.assertNotIn("org.freedesktop.portal", " ".join(args))
        self.assertNotIn("org.freedesktop.systemd1", " ".join(args))

    def test_unlocked_keyring_check_requests_no_secret_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bus"
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(path))
                with patch("claude_protect.keyring.socket_path", return_value=path), \
                        patch("ctypes.CDLL"), \
                        patch("claude_protect.keyring._call", side_effect=["(objectpath '/org/freedesktop/secrets/collection/login',)", "(<false>,)"]) as call:
                    result = verify()
        self.assertTrue(result["default_collection_unlocked"])
        self.assertEqual(result["actual_browser_backend"], "not_observed")
        self.assertEqual([entry.args[1] for entry in call.call_args_list],
                         ["org.freedesktop.Secret.Service.ReadAlias", "org.freedesktop.DBus.Properties.Get"])

    def test_locked_or_missing_collection_blocks_instead_of_requesting_basic_store(self):
        for replies in (["(objectpath '/',)"], ["(objectpath '/org/freedesktop/secrets/collection/login',)", "(<true>,)"]):
            with self.subTest(replies=replies), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "bus"
                with socket.socket(socket.AF_UNIX) as server:
                    server.bind(str(path))
                    with patch("claude_protect.keyring.socket_path", return_value=path), patch("ctypes.CDLL"), \
                            patch("claude_protect.keyring._call", side_effect=replies), self.assertRaises(RuntimeError):
                        verify()

    def test_missing_libsecret_blocks_startup(self):
        with patch("ctypes.CDLL", side_effect=OSError), self.assertRaisesRegex(RuntimeError, "libsecret"):
            verify()

    def test_application_uses_filtered_bus_and_preserves_user_locale(self):
        user = types.SimpleNamespace(pw_dir="/home/tester", pw_uid=1000, pw_name="tester")
        env = app_environment(Config(uid=1000), user, {"LANG": "zh_CN.UTF-8", "LC_TIME": "de_DE.UTF-8", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"})
        self.assertEqual(env["LANG"], "zh_CN.UTF-8")
        self.assertEqual(env["LC_TIME"], "de_DE.UTF-8")
        self.assertEqual(env["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1000/claude-protect-keyring/bus")
