#!/usr/bin/env python3
"""Repair an inactive external-proxy installation rejected by TUN route checks."""
import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from claude_protect.config import CONFIG, STATE, NAMESPACE, atomic_json, load_config, trusted_file

SERVICES = [f"claude-protect-{name}.service" for name in ("network", "relay", "status")]
LIBRARY = Path("/usr/local/lib/claude-protect/claude_protect")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-port", type=int, required=True, help="existing HTTP/mixed proxy port on 127.0.0.1")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("run with sudo; the repair updates installed system files")
    config = load_config()
    if config.proxy_mode != "external":
        parser.error("this repair is only for external-proxy installations")
    config = replace(config, upstream_port=args.proxy_port)
    if Path(f"/run/netns/{NAMESPACE}").exists() or STATE.exists():
        parser.error("an existing namespace/state requires inspection; refusing to overwrite it")
    for service in SERVICES:
        result = subprocess.run(["/usr/bin/systemctl", "show", service, "-p", "ActiveState", "--value"],
                                capture_output=True, text=True, check=True)
        if result.stdout.strip() not in ("failed", "inactive"):
            parser.error(f"{service} is not inactive; refusing to update a running installation")
    trusted_file(LIBRARY / "kernel.py")
    trusted_file(LIBRARY / "__init__.py")
    if (LIBRARY / "__init__.py").read_bytes() != (ROOT / "lib/claude_protect/__init__.py").read_bytes():
        parser.error("installed/source versions differ; use the documented upgrade procedure")
    with socket.create_connection(("127.0.0.1", config.upstream_port), timeout=3):
        pass
    # Validate the new collision check against this host before changing files.
    from claude_protect.kernel import ensure_no_collision
    ensure_no_collision(config)
    backup = Path(tempfile.mkdtemp(prefix="tun-repair-", dir=CONFIG.parent))
    shutil.copy2(CONFIG, backup / "config.json")
    shutil.copy2(LIBRARY / "kernel.py", backup / "kernel.py")
    print(f"原文件已备份到 {backup}", flush=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=LIBRARY, prefix=".kernel-repair-", delete=False) as output:
            temporary = Path(output.name)
            output.write((ROOT / "lib/claude_protect/kernel.py").read_bytes())
            os.fchmod(output.fileno(), 0o644)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(LIBRARY / "kernel.py")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    atomic_json(CONFIG, config.to_dict())
    subprocess.run(["/usr/bin/systemctl", "start", *SERVICES], check=True)
    for command in (
        ["/usr/local/libexec/claude-protect-helper", "status"],
        ["/usr/sbin/ip", "netns", "exec", NAMESPACE, "/usr/local/libexec/claude-protect-helper", "status"],
    ):
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if not json.loads(result.stdout).get("kernel_ok"):
            raise RuntimeError("服务启动后策略核对未通过，请查看 claude-protect status")
    print("隔离服务已核对。请回到控制面板刷新状态；插件仍需单独安装。", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"修复未完成：{error}", file=sys.stderr)
        raise SystemExit(1)
