import copy
from datetime import datetime, timedelta, timezone
import unittest

from claude_protect.diagnostics import EGRESS_TARGET, STREAM_TARGET
from claude_protect.inspection import checklist, fresh

NOW = datetime(2026, 10, 25, 10, 0, tzinfo=timezone.utc)
STAMP = NOW.isoformat()


def healthy():
    return {"installed": True, "status": {"kernel_ok": True, "upstream_managed": True}, "status_checked_at": STAMP,
            "keyring": {"checked_at": STAMP, "available": True, "default_collection_unlocked": True, "filtered_bus": True},
            "probe": {"checked_at": STAMP, "passed": True, "checks": {key: True for key in
                       ("udp_dns_denied", "tcp_dns_denied", "dot_denied", "system_dns_denied", "direct_ipv6_denied",
                        "direct_ipv4_denied", "runtime_isolated", "runtime_isolated_after", "namespace_matches", "proxy_tls_verified")}},
            "audit": {"checked_at": STAMP, "scope": "current_process_environment_only", "findings": []},
            "egress": {"checked_at": STAMP, "target": EGRESS_TARGET, "status": "complete", "stable_during_sample": True},
            "streaming": {"checked_at": STAMP, "target": STREAM_TARGET, "status": "passed"}, "now": NOW}


def states(result):
    return {item["id"]: item["state"] for item in result["items"]}


class InspectionTests(unittest.TestCase):
    def test_uninstalled_and_untested_are_never_green_or_given_a_risk_score(self):
        result = checklist(now=NOW)
        self.assertEqual(result["counts"]["pass"], 0)
        self.assertEqual(states(result)["installation"], "fix")
        self.assertNotIn("score", result)
        self.assertEqual(result["recommendations"][0]["action"], "configure")

    def test_even_healthy_technical_checks_leave_browser_and_reputation_unverified(self):
        result = checklist(**healthy())
        self.assertEqual(result["counts"]["pass"], 9)
        self.assertEqual(states(result)["browser"], "pending")
        self.assertEqual(states(result)["reputation"], "pending")
        self.assertEqual(result["account_safety"], "not_assessed")

    def test_expired_naive_future_or_invalid_timestamps_do_not_count_as_verified(self):
        for value in ((NOW - timedelta(seconds=601)).isoformat(), "2026-10-25T10:00:00", "invalid", (NOW + timedelta(seconds=90)).isoformat()):
            self.assertFalse(fresh({"checked_at": value}, NOW))
        data = healthy()
        for key in ("keyring", "probe", "audit", "egress", "streaming"):
            data[key]["checked_at"] = (NOW - timedelta(minutes=11)).isoformat()
        result = states(checklist(**data))
        self.assertTrue(all(result[key] == "pending" for key in ("keyring", "dns", "ipv6", "connectivity", "environment", "egress", "streaming")))

    def test_unready_or_stale_kernel_overrides_cached_online_success(self):
        for state in ({"kernel_ok": False}, {"kernel_ok": "true"}):
            data = healthy()
            data["status"] = state
            result = states(checklist(**data))
            self.assertEqual(result["installation"], "fix")
            self.assertEqual(result["dns"], "pending")
            self.assertEqual(result["egress"], "pending")
        data = healthy()
        data["status_checked_at"] = (NOW - timedelta(seconds=46)).isoformat()
        self.assertEqual(states(checklist(**data))["installation"], "pending")

    def test_external_and_test_upstream_have_specific_settings_advice(self):
        data = healthy()
        data["status"]["upstream_managed"] = False
        result = checklist(**data)
        self.assertEqual(states(result)["upstream"], "warn")
        row = next(item for item in result["items"] if item["id"] == "upstream")
        self.assertIn("DIRECT", row["advice"])
        data["status"]["upstream_test_only"] = True
        self.assertEqual(states(checklist(**data))["upstream"], "fix")

    def test_complete_external_checks_sync_without_claiming_managed_enforcement(self):
        data = healthy()
        data["status"]["upstream_managed"] = False
        data["upstream"] = {"checked_at": STAMP, "status": "complete", "items": [
            {"id": identifier, "state": "pass"} for identifier in ("controller", "route", "dns", "egress", "failover")]}
        result = checklist(**data)
        row = next(item for item in result["items"] if item["id"] == "upstream")
        self.assertEqual(row["state"], "pass")
        self.assertIn("不等于强制约束", row["advice"])
        self.assertFalse(data["status"]["upstream_managed"])
        for change in ("missing", "warning", "stale"):
            with self.subTest(change=change):
                changed = copy.deepcopy(data)
                if change == "missing":
                    changed["upstream"]["items"].pop()
                elif change == "warning":
                    changed["upstream"]["items"][2]["state"] = "warn"
                else:
                    changed["upstream"]["checked_at"] = (NOW - timedelta(minutes=11)).isoformat()
                self.assertEqual(states(checklist(**changed))["upstream"], "warn")

    def test_negative_dns_without_positive_control_cannot_pass(self):
        data = healthy()
        data["probe"]["checks"]["proxy_tls_verified"] = False
        result = states(checklist(**data))
        self.assertEqual(result["dns"], "warn")
        self.assertEqual(result["ipv6"], "warn")

    def test_locked_keyring_points_to_settings_without_claiming_backend_security(self):
        data = healthy()
        data["keyring"]["available"] = False
        result = checklist(**data)
        row = next(item for item in result["items"] if item["id"] == "keyring")
        self.assertEqual(row["state"], "fix")
        self.assertEqual(row["action"], "keyring-settings")
        self.assertIn("解锁", row["advice"])

    def test_exit_change_and_buffered_stream_produce_actionable_warnings(self):
        data = healthy()
        data["egress"]["changed_since_previous"] = True
        data["streaming"]["status"] = "inconclusive"
        result = checklist(**data)
        self.assertEqual(states(result)["egress"], "warn")
        self.assertEqual(states(result)["streaming"], "warn")
        self.assertTrue(any(item["action"] == "egress" for item in result["recommendations"]))

    def test_preview_has_no_real_result_even_when_given_healthy_fixtures(self):
        result = checklist(**healthy(), preview=True)
        self.assertEqual(result["counts"]["pass"], 0)
        self.assertTrue(all(item["state"] == "pending" for item in result["items"]))


if __name__ == "__main__":
    unittest.main()
