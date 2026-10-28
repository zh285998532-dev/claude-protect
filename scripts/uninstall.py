#!/usr/bin/env python3
"""Remove system integration; keep the user's profile and external proxy untouched."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys


def run(*args):
    subprocess.run(args, check=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}, cwd="/")


if sys.platform != "linux" or os.geteuid() != 0:
    raise SystemExit("Run explicitly with sudo on Ubuntu.")
source_lib = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(source_lib) if (source_lib / "claude_protect/restoration.py").is_file()
                else "/usr/local/lib/claude-protect")
from claude_protect.restoration import verify_network_removed
helper = "/usr/local/libexec/claude-protect-helper"
if not Path("/etc/claude-protect/config.json").exists():
    raise SystemExit("No installed configuration was found; no system objects were changed.")
configuration = json.loads(Path("/etc/claude-protect/config.json").read_text())
install_state_path = Path("/etc/claude-protect/install-state.json")
install_state = json.loads(install_state_path.read_text()) if install_state_path.exists() else {}
import pwd
desktop = pwd.getpwuid(configuration["uid"])
# Refuse before stopping services if any protected process is still alive.
result = subprocess.run(["/usr/sbin/ip", "netns", "pids", "claude-protect"], capture_output=True, text=True)
if result.returncode == 0 and result.stdout.strip():
    raise SystemExit("Close the protected VS Code window and all its child processes first. Nothing was removed.")
keyring_unit = Path("/usr/local/lib/systemd/user/claude-protect-keyring.service")
if keyring_unit.exists():
    runtime = Path(f"/run/user/{desktop.pw_uid}")
    user_command = ["/usr/sbin/runuser", "-u", desktop.pw_name, "--", "/usr/bin/env",
                    f"XDG_RUNTIME_DIR={runtime}", f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus",
                    "/usr/bin/systemctl", "--user"]
    stop = subprocess.run(user_command + ["stop", "claude-protect-keyring.service"], capture_output=True)
    if stop.returncode and (runtime / "claude-protect-keyring/bus").exists():
        raise SystemExit("Cannot stop the keyring proxy; no protection services were removed.")
    keyring_unit.unlink()
    subprocess.run(user_command + ["daemon-reload"], capture_output=True)
for name in ("relay", "status", "upstream", "network"):
    if Path(f"/etc/systemd/system/claude-protect-{name}.service").exists():
        run("/usr/bin/systemctl", "disable", "--now", f"claude-protect-{name}.service")
# Also handle a partial installation whose network unit never reached active.
run(helper, "teardown")
# Keep configuration, credentials and ownership metadata if cleanup is unverified.
verify_network_removed(managed=configuration.get("proxy_mode") == "managed")
for name in ("relay", "status", "upstream", "network"):
    Path(f"/etc/systemd/system/claude-protect-{name}.service").unlink(missing_ok=True)
for name in ("helper", "relay", "status", "probe", "open", "upstream", "session"):
    Path(f"/usr/local/libexec/claude-protect-{name}").unlink(missing_ok=True)
for path in ("/usr/local/bin/claude-protect", "/etc/sudoers.d/claude-protect",
             "/usr/local/share/applications/claude-protect.desktop",
             "/usr/local/share/applications/claude-protect-browser.desktop"):
    Path(path).unlink(missing_ok=True)
for path in ("/usr/local/lib/claude-protect", "/usr/local/share/claude-protect", "/etc/claude-protect", "/run/claude-protect"):
    if Path(path).exists():
        shutil.rmtree(path, ignore_errors=False)
if install_state.get("created_proxy_user"):
    run("/usr/sbin/userdel", "claude-protect-proxy")
run("/usr/bin/systemctl", "daemon-reload")
print("已核对：专用 namespace、网络接口、上游防火墙表已移除，专用系统服务已停止。")
print("系统组件已还原（移除）。用户 VS Code / 浏览器数据、Claude 登录资料、项目和外部代理配置已保留。")
print("主机原有 DNS、默认路由、系统代理和全局 IPv6 设置不由本项目重置。需要继续使用保护时，请重新安装组件。")
