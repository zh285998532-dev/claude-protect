"""Read-only verification of project network cleanup; never resets host networking."""
import json
from pathlib import Path
import subprocess


def capture(argv):
    result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=12,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}, cwd="/")
    if result.returncode:
        raise RuntimeError("无法核对还原结果：系统查询失败，未宣称清理完成。")
    return result.stdout


def verify_network_removed(*, query=capture, exists=lambda path: Path(path).exists(), managed=False):
    """Called as root after helper teardown, before deleting ownership metadata."""
    if exists("/run/netns/claude-protect") or exists("/sys/class/net/cp-host"):
        raise RuntimeError("专用 namespace 或网络接口仍存在，已停止后续删除；请查看终端错误。")
    tables = json.loads(query(["/usr/sbin/nft", "-j", "list", "tables"]))
    if not isinstance(tables, dict) or not isinstance(tables.get("nftables"), list):
        raise RuntimeError("防火墙核对结果无效，未宣称还原完成。")
    for item in tables["nftables"]:
        table = item.get("table", {}) if isinstance(item, dict) else {}
        if table.get("family") == "inet" and table.get("name") == "claude_protect_upstream":
            raise RuntimeError("专用上游防火墙表仍存在，保留配置与归属记录以便修复。不会清空其他防火墙规则。")
    services = ("network", "relay", "status", "upstream") if managed else ("network", "relay", "status")
    for name in services:
        output = query(["/usr/bin/systemctl", "show", f"claude-protect-{name}.service",
                        "--property=ActiveState", "--property=MainPID"])
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if properties.get("ActiveState") not in ("inactive", "failed") or properties.get("MainPID") != "0":
            raise RuntimeError(f"专用 {name} 服务未确认停止，保留配置供检查。")
    return {"namespace_removed": True, "interface_removed": True, "upstream_table_removed": True,
            "services_stopped": True, "host_network_reset": False}
