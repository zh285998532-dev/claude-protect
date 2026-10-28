import copy
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from claude_protect.browser import validate_url
from claude_protect.config import Config, atomic_json
from claude_protect.helper import app_environment, application_command, caller
from claude_protect.kernel import nft_policy, rules_digest, topology_ok


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = Config(uid=1000)
        self.user = types.SimpleNamespace(pw_dir="/home/test user", pw_uid=1000, pw_gid=1000, pw_name="tester")

    def test_rejects_untrusted_configuration_values(self):
        for fields in ({"uid": 0}, {"uid": True}, {"uid": 1000, "relay_port": True},
                       {"uid": 1000, "upstream_port": 0}, {"uid": 1000, "subnet": "0.0.0.0/30"},
                       {"uid": 1000, "subnet": "10.0.0.0/24"}, {"uid": 1000, "code": "/tmp/code"},
                       {"uid": 1000, "subnet": "10.0.0.1/30"}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                Config(**fields)

    def test_sudo_uid_cannot_choose_another_user(self):
        for environment in ({}, {"SUDO_UID": "0"}, {"SUDO_UID": "1001"}):
            with patch.dict(os.environ, environment, clear=True), self.assertRaises(RuntimeError):
                caller(self.config)

    def test_environment_does_not_forward_injection_or_credentials(self):
        inherited = {"LD_PRELOAD": "/tmp/bad.so", "PYTHONPATH": "/tmp", "NODE_OPTIONS": "--require=/tmp/bad",
                     "ANTHROPIC_API_KEY": "secret", "ANTHROPIC_BASE_URL": "https://other.example",
                     "HTTPS_PROXY": "http://other.example", "https_proxy": "http://other.example",
                     "NODE_TLS_REJECT_UNAUTHORIZED": "0", "NO_PROXY": "*", "DISPLAY": ":1"}
        environment = app_environment(self.config, self.user, inherited)
        for key in ("LD_PRELOAD", "PYTHONPATH", "NODE_OPTIONS", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "NODE_TLS_REJECT_UNAUTHORIZED"):
            self.assertNotIn(key, environment)
        self.assertEqual(environment["HTTPS_PROXY"], self.config.proxy_url)
        self.assertEqual(environment["https_proxy"], self.config.proxy_url)
        self.assertNotEqual(environment["NO_PROXY"], "*")
        self.assertEqual(environment["DISPLAY"], ":1")

    def test_workspace_is_an_argument_never_shell_code(self):
        with tempfile.TemporaryDirectory(prefix="cp-$(do-not-execute)-") as folder:
            command = application_command(self.config, self.user, "code", folder)
            self.assertEqual(command[-1], folder)
            self.assertEqual(command[0], "/usr/bin/code")
        with self.assertRaises(ValueError):
            application_command(self.config, self.user, "code", "--no-sandbox")
        with self.assertRaises(ValueError):
            application_command(self.config, self.user, "shell", "/bin/sh")

    def test_only_official_extension_can_be_installed_by_helper(self):
        command = application_command(self.config, self.user, "install-official")
        self.assertEqual(command[-2:], ["--install-extension", "anthropic.claude-code"])
        self.assertIn("--user-data-dir", command)
        self.assertIn("--extensions-dir", command)

    def test_dns_drop_precedes_loopback_allow_and_no_global_ipv6_change(self):
        policy = nft_policy(self.config)
        self.assertLess(policy.index("th dport { 53, 853 }"), policy.index('oifname "lo"'))
        self.assertIn("policy drop", policy)
        self.assertIn(f"ip daddr {self.config.gateway} tcp dport {self.config.relay_port}", policy)
        self.assertNotIn("masquerade", policy)
        self.assertNotIn("redirect", policy)

    def test_firewall_counts_do_not_change_digest_but_accept_rules_do(self):
        baseline = {"nftables": [{"metainfo": {"version": "a"}}, {"chain": {"handle": 1, "policy": "drop"}},
                                {"rule": {"handle": 2, "expr": [{"counter": {"packets": 2, "bytes": 20}}, {"drop": None}]}}]}
        changed = copy.deepcopy(baseline)
        changed["nftables"][0]["metainfo"]["version"] = "b"
        changed["nftables"][1]["chain"]["handle"] = 30
        changed["nftables"][2]["rule"]["expr"][0]["counter"]["packets"] = 100
        self.assertEqual(rules_digest(baseline), rules_digest(changed))
        changed["nftables"][1]["chain"]["policy"] = "accept"
        self.assertNotEqual(rules_digest(baseline), rules_digest(changed))

    def test_extra_route_or_address_invalidates_topology(self):
        observed = {"routes": [{"dst": self.config.subnet, "dev": "cp0", "scope": "link"}],
                    "routes6": [], "addresses": [{"local": self.config.client, "prefixlen": 30, "family": "inet"}]}
        self.assertTrue(topology_ok(self.config, observed))
        for field, value in (("routes", {"dst": "default", "gateway": self.config.gateway}),
                             ("routes6", {"dst": "default", "gateway": "fe80::1"}),
                             ("addresses", {"local": "10.0.0.1", "prefixlen": 24, "family": "inet"})):
            changed = copy.deepcopy(observed)
            changed[field].append(value)
            self.assertFalse(topology_ok(self.config, changed))

    def test_oauth_handler_rejects_other_schemes_and_extensions(self):
        for url in ("file:///etc/passwd", "javascript:alert(1)", "https://user:pass@example.com",
                    "vscode://other.extension/callback", "https://example.com\n--no-sandbox", "--no-sandbox"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)
        url = "vscode://anthropic.claude-code/callback?state=opaque&code=opaque"
        self.assertEqual(validate_url(url), url)

    def test_atomic_json_leaves_no_partial_files(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "state.json"
            atomic_json(target, {"old": 1})
            atomic_json(target, {"new": 2})
            self.assertEqual(json.loads(target.read_text()), {"new": 2})
            self.assertEqual([p.name for p in Path(folder).iterdir()], ["state.json"])


if __name__ == "__main__":
    unittest.main()
