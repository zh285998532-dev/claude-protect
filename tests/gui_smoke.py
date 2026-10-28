"""Optional real Qt rendering/interaction checks; no Ubuntu services or accounts.

Run: QT_QPA_PLATFORM=offscreen python tests/gui_smoke.py [--screenshots DIR]
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication
from claude_protect.gui import Panel
from claude_protect.config import Config
from claude_protect.diagnostics import EGRESS_TARGET, STREAM_TARGET
from claude_protect.diagnostics import timestamp

APPLICATION = QApplication.instance() or QApplication([sys.argv[0]])
APPLICATION.setStyle("Fusion")
FONT = QFont()
FONT.setFamilies(["Noto Sans CJK SC", "PingFang SC", "sans-serif"])
FONT.setPointSize(10)
APPLICATION.setFont(FONT)


class GuiSmokeTests(unittest.TestCase):
    def test_connection_page_reads_installed_proxy_and_extension_state_on_refresh(self):
        self.panel.demo = False
        config = Config(uid=1000, upstream_port=7897)
        versions = {"claude-protect-local.claude-protect": "0.6.0", "anthropic.claude-code": "2.1.310"}
        with patch("claude_protect.gui.CONFIG") as path, \
                patch("claude_protect.gui.load_config", return_value=config, create=True), \
                patch("claude_protect.gui.missing_dependencies", return_value=[], create=True), \
                patch("claude_protect.gui.extension_versions", return_value=(versions, ""), create=True), \
                patch.object(self.panel, "command"):
            path.exists.return_value = True
            self.panel.refresh()
            self.panel._status_done(0, json.dumps({"kernel_ok": True, "upstream_managed": False}))
            self.assertEqual(self.panel.mode.currentData(), "external")
            self.assertEqual(self.panel.local_port.text(), "7897")
            self.assertTrue(self.panel.local_port.isReadOnly())
            self.assertFalse(self.panel.mode.isEnabled())
            self.assertIn("已安装", self.panel.install_button.text())
            self.assertIn("已核对", self.panel.install_button.text())
            self.assertIn("已安装", self.panel.protect_plugin_status.text())
            self.assertIn("2.1.310", self.panel.official_plugin_status.text())
            self.assertFalse(self.panel.protect_plugin_button.isEnabled())
            self.assertFalse(self.panel.official_plugin_button.isEnabled())
            self.panel._status_done(1, "status unavailable")
            self.assertIn("未通过", self.panel.install_button.text())
            self.assertNotIn("已核对", self.panel.install_button.text())
            path.exists.return_value = False
            self.panel.refresh()
            self.assertFalse(self.panel.local_port.isReadOnly())
            self.assertTrue(self.panel.mode.isEnabled())
            self.assertTrue(self.panel.install_button.isEnabled())

    def test_configuration_read_failure_cannot_look_like_verified_installation(self):
        self.panel.demo = False
        with patch("claude_protect.gui.CONFIG") as path, \
                patch("claude_protect.gui.load_config", side_effect=PermissionError("unreadable")), \
                patch("claude_protect.gui.missing_dependencies", return_value=["nft"]), \
                patch("claude_protect.gui.extension_versions", return_value=({}, "无法核对插件清单")), \
                patch.object(self.panel, "command"):
            path.exists.return_value = True
            self.panel.refresh()
            self.panel._status_done(0, json.dumps({"kernel_ok": True}))
            self.assertIn("校验未通过", self.panel.install_button.text())
            self.assertIn("nft", self.panel.dependencies_note.text())
            self.assertIn("无法核对", self.panel.protect_plugin_status.text())
            self.assertFalse(self.panel.install_button.isEnabled())
            self.assertFalse(self.panel.protect_plugin_button.isEnabled())

    def setUp(self):
        self.panel = Panel(demo=True)
        self.panel.show()
        QTest.qWait(30)

    def tearDown(self):
        self.panel.close()
        self.panel.deleteLater()
        APPLICATION.processEvents()

    def test_demo_disables_system_actions_and_never_spawns(self):
        self.assertTrue(all(not button.isEnabled() for button in self.panel.live_buttons))
        with patch("claude_protect.gui.subprocess.Popen") as launch, patch("claude_protect.gui.QProcess") as execute:
            self.panel.refresh()
            self.panel.install_core()
            self.panel.launch("code", ["/should/not/run"])
            self.panel.command("status", ["/should/not/run"], lambda *args: None)
            launch.assert_not_called()
            execute.assert_not_called()

    def test_navigation_mode_and_robot_render_without_clipping_page_width(self):
        for index in range(len(self.panel.nav_buttons)):
            QTest.mouseClick(self.panel.nav_buttons[index], Qt.MouseButton.LeftButton)
            self.assertEqual(self.panel.pages.currentIndex(), index)
            scroll = self.panel.pages.currentWidget()
            self.assertLessEqual(scroll.widget().minimumSizeHint().width(), scroll.viewport().width())
        self.panel.mode.setCurrentIndex(1)
        self.assertEqual(self.panel.mode_forms.currentIndex(), 1)
        for mood in ("idle", "busy", "ready", "alert"):
            self.panel.robot.set_mood(mood)
            self.assertFalse(self.panel.robot.grab().isNull())

    def test_real_qprocess_does_not_block_event_loop_or_treat_failed_status_as_ready(self):
        self.panel.demo = False
        ticks = []
        result = []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        self.panel.command("fixture", [sys.executable, "-c", "import time; time.sleep(.15); print('done')"],
                           lambda code, text: result.append((code, text)), timeout=3000)
        deadline = time.monotonic() + 4
        while not result and time.monotonic() < deadline:
            QTest.qWait(20)
        timer.stop()
        self.assertEqual(result[0][0], 0)
        self.assertIn("done", result[0][1])
        self.assertGreater(len(ticks), 2)
        self.panel._status_done(1, json.dumps({"kernel_ok": True}))
        self.assertIsNone(self.panel.status_data)
        self.assertFalse(self.panel.code_button.isEnabled())

    def test_timeout_is_a_failure_and_clears_prior_checks(self):
        self.panel.demo = False
        result = []
        self.panel.command("fixture", [sys.executable, "-c", "import time; time.sleep(5)"],
                           lambda code, text: result.append((code, text)), timeout=70)
        deadline = time.monotonic() + 3
        while not result and time.monotonic() < deadline:
            QTest.qWait(20)
        self.assertEqual(result[0][0], -1)
        self.assertIn("超时", result[0][1])
        self.panel.probe_data = {"passed": True}
        self.panel.keyring_data = {"available": True}
        self.panel._status_done(1, "unavailable")
        self.assertIsNone(self.panel.probe_data)
        self.assertIsNone(self.panel.keyring_data)

    def test_closing_panel_does_not_terminate_launched_application(self):
        self.panel.demo = False
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "finished"
            program = f"import time; from pathlib import Path; time.sleep(.15); Path({str(marker)!r}).write_text('ok')"
            self.panel.launch("fixture", [sys.executable, "-c", program])
            self.panel.close()
            deadline = time.monotonic() + 3
            while not marker.exists() and time.monotonic() < deadline:
                QTest.qWait(20)
            self.assertEqual(marker.read_text(), "ok")

    def test_failed_exit_observation_and_changed_policy_cannot_retain_stale_success(self):
        self.panel.demo = False
        self.panel.egress_data = {"status": "complete", "observed_ips": ["8.8.8.8"]}
        with patch("pathlib.Path.is_file", return_value=True), patch.object(self.panel, "command") as command:
            self.panel.observe_egress()
            callback = command.call_args.args[2]
            callback(1, json.dumps({"target": EGRESS_TARGET, "scope": "protected_namespace_to_ipify_only", "status": "complete"}))
            self.assertEqual(self.panel.egress_data["status"], "failed")
            self.assertNotIn("8.8.8.8", self.panel.egress_summary.text())
            self.panel.check_stream()
            callback = command.call_args.args[2]
            self.panel.state_signature = "policy-changed"
            callback(0, json.dumps({"target": STREAM_TARGET, "scope": "generic_httpbin_https_stream_only", "status": "passed"}))
            self.assertEqual(self.panel.streaming_data["status"], "failed")
            self.assertNotIn("本次滴流样本通过", self.panel.core_summary.text())

    def test_offline_audit_does_not_spawn_a_process_or_access_network(self):
        self.panel.demo = False
        with patch("claude_protect.gui.subprocess.Popen") as launch, patch("claude_protect.gui.QProcess") as execute, \
                patch("os.environ", {"LANG": "zh_CN.UTF-8"}):
            self.panel.run_audit()
            launch.assert_not_called()
            execute.assert_not_called()
            self.assertEqual(self.panel.audit_data["scope"], "current_process_environment_only")
            self.assertIn("zh_CN.UTF-8", self.panel.audit_summary.text())

    def test_external_proxy_button_runs_packaged_detector_and_clears_failed_or_stale_success(self):
        from claude_protect.config import Config
        from claude_protect.external_audit import ITEMS, SCOPE, policy_context
        self.panel.demo = False
        self.panel.installed_config = Config(uid=1000, upstream_port=7897)
        self.panel.status_data = {"kernel_ok": True, "upstream_managed": False}
        result = {"schema": 1, "scope": SCOPE, "checked_at": timestamp(), "status": "complete",
                  "policy_context": policy_context(self.panel.installed_config),
                  "items": [{"id": key, "state": "pending" if key == "failover" else "warn" if key == "dns" else "pass",
                             "detail": "fixture evidence"} for key in ITEMS], "egress": {"ips": ["8.8.8.8"]}}
        with patch.object(self.panel, "command") as command, \
                patch.object(self.panel.history, "record", return_value={"records": [], "changed_since_previous": None}):
            self.panel.render()
            self.assertTrue(self.panel.upstream_button.isEnabled())
            QTest.mouseClick(self.panel.upstream_overview_button, Qt.MouseButton.LeftButton)
            self.assertEqual(self.panel.pages.currentIndex(), 2)
            self.assertTrue(command.call_args.args[1][-1].endswith("external_audit.py"))
            callback = command.call_args.args[2]
            callback(0, json.dumps(result))
            self.assertEqual(self.panel.upstream_table.rowCount(), 5)
            self.assertIn("已自动检测", self.panel.tiles[1][1].text())
            self.assertIn("8.8.8.x", self.panel.upstream_table.item(3, 2).text())
            self.assertEqual(self.panel.upstream_table.item(4, 1).text(), "未能验证")
            self.panel.upstream_data["checked_at"] = "2020-01-01T00:00:00+00:00"
            self.panel.render_upstream()
            self.assertEqual(self.panel.upstream_table.item(0, 1).text(), "未能验证")
            result["checked_at"] = timestamp()
            callback(1, json.dumps(result))
            self.assertEqual(self.panel.upstream_data["status"], "failed")
            self.assertEqual(self.panel.upstream_table.rowCount(), 0)
            callback(0, json.dumps(result))
            self.panel.state_signature = "changed"
            callback(0, json.dumps(result))
            self.assertEqual(self.panel.upstream_data["status"], "failed")

    def test_external_proxy_detection_is_disabled_in_demo_and_on_managed_upstream(self):
        from claude_protect.config import Config
        with patch.object(self.panel, "command") as command:
            self.panel.run_upstream_check()
            command.assert_not_called()
            self.panel.demo = False
            self.panel.status_data = {"kernel_ok": True, "upstream_managed": True}
            self.panel.installed_config = Config(uid=1000, proxy_mode="managed", proxy_uid=999,
                                                upstream_ip="8.8.8.8", upstream_tls_name="proxy.example")
            self.panel.render()
            self.assertFalse(self.panel.upstream_button.isEnabled())
            self.panel.run_upstream_check()
            command.assert_not_called()

    def test_five_external_passes_render_green_and_expired_results_clear_green(self):
        from claude_protect.external_audit import ITEMS
        from claude_protect.gui import COLORS
        self.panel.demo = False
        self.panel.installed_config = Config(uid=1000, upstream_port=7897)
        self.panel.status_data = {"kernel_ok": True, "upstream_managed": False}
        self.panel.upstream_data = {"checked_at": timestamp(), "status": "complete", "items": [
            {"id": key, "state": "pass", "detail": "fixture evidence"} for key in ITEMS]}
        self.panel.render()
        tile = self.panel.tiles[1][1]
        self.assertIn(COLORS["good"], tile.styleSheet())
        self.assertEqual(tile.text(), "本次通过")
        self.assertFalse(self.panel.status_data["upstream_managed"])
        self.panel.upstream_data["checked_at"] = "2020-01-01T00:00:00+00:00"
        self.panel.render()
        self.assertNotIn(COLORS["good"], tile.styleSheet())

    def test_one_click_flow_calls_external_detector_before_optional_stream(self):
        self.panel.demo = False
        callbacks = []
        with patch.object(self.panel, "refresh", side_effect=lambda *, after=None: callbacks.append(after)):
            self.panel.start_inspection()
            self.assertEqual([name for name, operation in self.panel.inspection_steps],
                             ["密钥链通道", "DNS / IPv6 / 连通性", "实际出口", "外部代理", "20 秒流式样本"])
            self.assertEqual(self.panel.inspection_steps[3][1], self.panel.run_upstream_check)
            self.panel.cancel_inspection()
            callbacks[0]()

    def test_runtime_dns_button_uses_fixed_read_only_admin_action_and_reruns_check(self):
        from claude_protect.config import Config
        self.panel.demo = False
        self.panel.status_data = {"kernel_ok": True}
        self.panel.installed_config = Config(uid=1000, upstream_port=7897)
        with patch.object(self.panel, "launch") as launch:
            self.panel.read_dns_runtime()
            self.assertEqual(launch.call_args.args[0], "dns-admin")
            command = launch.call_args.args[1]
            self.assertIn("/usr/bin/sudo", command)
            self.assertEqual(command[-1], "--read-runtime-dns")
        with patch.object(self.panel, "refresh") as refresh:
            self.panel.events.put(("dns-admin", 0, ""))
            self.panel._drain_events()
            self.assertEqual(refresh.call_args.kwargs["after"], self.panel.run_upstream_check)

    def test_external_exit_success_updates_general_inspection_without_a_second_test(self):
        from claude_protect.config import Config
        from claude_protect.external_audit import ITEMS, SCOPE, policy_context
        self.panel.demo = False
        self.panel.installed_config = Config(uid=1000, upstream_port=7897)
        self.panel.status_data = {"kernel_ok": True, "upstream_managed": False}
        self.panel.status_checked_at = timestamp()
        result = {"schema": 1, "scope": SCOPE, "status": "complete", "checked_at": timestamp(),
                  "policy_context": policy_context(self.panel.installed_config),
                  "items": [{"id": key, "state": "warn" if key == "dns" else "pass", "detail": "evidence"} for key in ITEMS],
                  "egress": {"ips": ["8.8.8.8"], "stable": True}}
        with patch.object(self.panel, "command") as command, \
                patch.object(self.panel.history, "record", return_value={"records": [], "changed_since_previous": None}), \
                patch("claude_protect.gui.CONFIG") as config, patch("os.environ", {}):
            config.exists.return_value = True
            self.panel.run_upstream_check()
            command.call_args.args[2](0, json.dumps(result))
            self.assertIsNotNone(self.panel.egress_data)
            states = {item["id"]: item["state"] for item in self.panel.inspection_snapshot()["items"]}
            self.assertEqual(states["egress"], "pass")
            self.assertEqual(states["environment"], "pass")

    def test_one_click_check_runs_in_order_and_keeps_browser_items_unverified(self):
        self.panel.demo = False
        calls = []

        def step(name, destination=None):
            def run(*, after=None):
                calls.append(name)
                stamp = timestamp()
                if name == "status":
                    self.panel.status_data = {"kernel_ok": True, "upstream_managed": True}
                    self.panel.status_checked_at = stamp
                elif name == "keyring":
                    self.panel.keyring_data = {"checked_at": stamp, "available": True, "default_collection_unlocked": True, "filtered_bus": True}
                elif name == "probe":
                    self.panel.probe_data = {"checked_at": stamp, "passed": True, "checks": {key: True for key in
                        ("udp_dns_denied", "tcp_dns_denied", "dot_denied", "system_dns_denied", "direct_ipv6_denied",
                         "direct_ipv4_denied", "namespace_matches", "runtime_isolated", "runtime_isolated_after", "proxy_tls_verified")}}
                elif name == "egress":
                    self.panel.egress_data = {"checked_at": stamp, "target": EGRESS_TARGET, "status": "complete", "stable_during_sample": True}
                else:
                    self.panel.streaming_data = {"checked_at": stamp, "target": STREAM_TARGET, "status": "passed"}
                QTimer.singleShot(0, after)
            return run
        with patch("claude_protect.gui.CONFIG") as config, patch("pathlib.Path.is_file", return_value=True), \
                patch.object(self.panel, "refresh", side_effect=step("status")), \
                patch.object(self.panel, "check_keyring", side_effect=step("keyring")), \
                patch.object(self.panel, "run_probe", side_effect=step("probe")), \
                patch.object(self.panel, "observe_egress", side_effect=step("egress")), \
                patch.object(self.panel, "check_stream", side_effect=step("streaming")), patch("os.environ", {}):
            config.exists.return_value = True
            self.panel.start_inspection()
            deadline = time.monotonic() + 2
            while self.panel.inspection_running and time.monotonic() < deadline:
                QTest.qWait(10)
            self.assertEqual(calls, ["status", "keyring", "probe", "egress", "streaming"])
            self.assertFalse(self.panel.inspection_running)
            snapshot = self.panel.inspection_snapshot()
            self.assertEqual(snapshot["counts"]["pass"], 9)
            self.assertEqual(snapshot["counts"]["pending"], 2)

    def test_cancel_stops_future_steps_and_unready_status_skips_network(self):
        self.panel.demo = False
        callbacks = []
        with patch.object(self.panel, "refresh", side_effect=lambda *, after=None: callbacks.append(after)), \
                patch.object(self.panel, "check_keyring") as keyring, patch.object(self.panel, "run_probe") as probe:
            self.panel.start_inspection()
            self.panel.cancel_inspection()
            callbacks.pop()()
            self.assertFalse(self.panel.inspection_running)
            keyring.assert_not_called()
            probe.assert_not_called()
            self.panel.start_inspection()
            self.panel.status_data = None
            callbacks.pop()()
            self.assertFalse(self.panel.inspection_running)
            self.assertIn("跳过联网步骤", self.panel.inspection_run_note.text())
            probe.assert_not_called()

    def test_waiter_for_existing_command_advances_only_after_its_primary_callback(self):
        self.panel.demo = False
        events = []
        argv = [sys.executable, "-c", "import time; time.sleep(.1); print('ok')"]
        self.panel.command("shared-fixture", argv, lambda *args: events.append("primary"))
        self.panel.command("shared-fixture", argv, lambda *args: events.append("duplicate"), after=lambda: events.append("after"))
        deadline = time.monotonic() + 2
        while len(events) < 2 and time.monotonic() < deadline:
            QTest.qWait(20)
        self.assertEqual(events, ["primary", "after"])

    def test_netcoffee_uses_protected_browser_and_suggestions_open_configuration(self):
        self.panel.demo = False
        with patch.object(self.panel, "launch") as launch, patch("pathlib.Path.is_file", return_value=True):
            self.panel.status_data = {"kernel_ok": True}
            self.panel.open_netcoffee()
            self.assertEqual(launch.call_args.args[1], ["/usr/local/bin/claude-protect", "browser", "https://ip.net.coffee/claude/"])
            self.panel.inspection_action("configure")
            self.assertEqual(self.panel.pages.currentIndex(), 1)

    def test_export_contains_setting_reminders_but_not_raw_environment_secrets(self):
        self.panel.demo = False
        self.panel.audit_data = {"checked_at": timestamp(), "scope": "current_process_environment_only",
                                 "findings": [{"id": "api_key_present", "level": "attention", "message": "never-export-secret"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with patch("claude_protect.gui.QFileDialog.getSaveFileName", return_value=(str(path), "JSON")):
                self.panel.export_report()
            content = path.read_text()
            self.assertNotIn("never-export-secret", content)
            self.assertIn("inspection", json.loads(content))

    def test_restore_requires_confirmation_and_uses_only_project_uninstaller_in_terminal(self):
        from PySide6.QtWidgets import QMessageBox
        self.panel.demo = False
        with patch("claude_protect.gui.CONFIG") as config, patch("pathlib.Path.is_file", return_value=True), \
                patch("claude_protect.gui.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes) as confirm, \
                patch.object(self.panel, "launch") as launch:
            config.exists.return_value = True
            self.panel.uninstall_core()
            self.assertEqual(launch.call_args.args[0], "restore")
            argv = launch.call_args.args[1]
            self.assertIn("/usr/bin/sudo", argv)
            self.assertIn("/usr/local/share/claude-protect/uninstall.py", argv)
            self.assertNotIn("flush", argv)
            self.assertIn("保留", confirm.call_args.args[2])
            self.assertIn("凭据", confirm.call_args.args[2])

    def test_restore_does_not_start_while_inspection_is_running(self):
        self.panel.demo = False
        self.panel.inspection_running = True
        with patch.object(self.panel, "fail") as fail, patch.object(self.panel, "launch") as launch:
            self.panel.uninstall_core()
            fail.assert_called_once()
            launch.assert_not_called()

    def test_declining_restore_confirmation_does_not_launch_anything(self):
        from PySide6.QtWidgets import QMessageBox
        self.panel.demo = False
        with patch("claude_protect.gui.CONFIG") as config, patch("pathlib.Path.is_file", return_value=True), \
                patch("claude_protect.gui.QMessageBox.question", return_value=QMessageBox.StandardButton.No), \
                patch.object(self.panel, "launch") as launch:
            config.exists.return_value = True
            self.panel.uninstall_core()
            launch.assert_not_called()

    def test_restore_terminal_exit_alone_does_not_claim_configuration_removed(self):
        self.panel.demo = False
        with patch("claude_protect.gui.CONFIG") as config, patch.object(self.panel, "refresh"):
            config.exists.return_value = True
            self.panel.events.put(("restore", 0, ""))
            self.panel._drain_events()
            self.assertIn("配置仍存在", self.panel.restoration_note)
            config.exists.return_value = False
            self.panel.events.put(("restore", 0, ""))
            self.panel._drain_events()
            self.assertIn("配套配置已移除", self.panel.restoration_note)
            self.panel.events.put(("restore", 1, "failed"))
            self.panel._drain_events()
            self.assertIn("未完成", self.panel.restoration_note)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--screenshots", type=Path)
    args, rest = parser.parse_known_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
        panel = Panel(demo=True)
        panel.show()
        for index, name in ((0, "overview"), (1, "configuration"), (2, "diagnostics"), (3, "inspection")):
            panel.navigate(index)
            QTest.qWait(80)
            panel.grab().save(str(args.screenshots / f"claude-protect-{name}.png"))
        panel.close()
    unittest.main(argv=[sys.argv[0], *rest])
