#!/usr/bin/env python3
"""Explicit Ubuntu installer; never executed by extension activation."""
import argparse
import getpass
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from claude_protect.config import Config, CONFIG
from claude_protect import __version__
from claude_protect.keyring import user_unit

PROXY_USER = "claude-protect-proxy"


def command(*args):
    subprocess.run(args, check=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}, cwd="/")


def write(path, content, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink destination: {path}")
    path.write_text(content)
    os.chmod(path, mode)


def main():
    parser = argparse.ArgumentParser(description="Install Claude Protect on Ubuntu with systemd")
    parser.add_argument("--user", required=True, help="desktop login user, never root")
    parser.add_argument("--proxy-port", type=int, default=20808, help="existing local HTTP CONNECT proxy on 127.0.0.1")
    parser.add_argument("--subnet", default="10.254.253.0/30")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--upstream-ip", help="managed HTTPS CONNECT upstream: literal public IPv4")
    mode.add_argument("--external-proxy", action="store_true", help="legacy local proxy; upstream egress/DNS is NOT verified")
    parser.add_argument("--upstream-port", type=int, default=443)
    parser.add_argument("--upstream-tls-name", help="certificate verification/SNI name; never used for DNS")
    parser.add_argument("--upstream-auth", action="store_true", help="prompt locally for upstream username/password")
    parser.add_argument("--allow-test-upstream", action="store_true", help="disposable-test configuration only; permits private upstreams")
    parser.add_argument("--upstream-no-tls", action="store_true", help="only allowed with --allow-test-upstream, never production")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run explicitly with sudo on Ubuntu")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", args.user):
        parser.error("unsupported login username")
    user = pwd.getpwnam(args.user)
    if args.external_proxy and any((args.upstream_auth, args.upstream_tls_name, args.allow_test_upstream, args.upstream_no_tls)):
        parser.error("managed upstream options cannot be used with external-proxy")
    if args.upstream_no_tls and not args.allow_test_upstream:
        parser.error("plaintext upstream is test-only; production requires a verified TLS upstream")
    if args.upstream_auth and args.upstream_no_tls:
        parser.error("upstream credentials require TLS")
    values = dict(uid=user.pw_uid, upstream_port=args.proxy_port, subnet=args.subnet,
                  proxy_mode="external" if args.external_proxy else "managed")
    if args.upstream_ip:
        values.update(upstream_ip=args.upstream_ip, upstream_remote_port=args.upstream_port,
                      upstream_tls_name=args.upstream_tls_name, upstream_tls=not args.upstream_no_tls,
                      upstream_test_only=args.allow_test_upstream, proxy_uid=2147483647)
    # Validate all user-controlled policy fields before creating any system object.
    Config(**values)
    release = Path("/etc/os-release").read_text()
    if not re.search(r'^ID=ubuntu$', release, re.M):
        parser.error("targets Ubuntu; other Linux distributions need separate validation")
    if CONFIG.exists():
        parser.error("already installed; preserve your profile and uninstall before reinstalling this version")
    for executable in ("ip", "nft", "sysctl", "mount", "setpriv", "unshare", "nsenter", "systemctl", "visudo", "sudo", "xdg-dbus-proxy", "gdbus", "useradd", "userdel"):
        if not shutil.which(executable):
            parser.error(f"missing dependency: {executable}; see README apt prerequisites")
    vsix = ROOT / f"dist/claude-protect-{__version__}.vsix"
    if not vsix.is_file():
        parser.error("build the VSIX first, or use the source distribution containing dist/")
    credentials = {"username": "", "password": ""}
    if args.upstream_auth:
        if not sys.stdin.isatty():
            parser.error("authentication setup requires an interactive local terminal")
        credentials = {"username": input("Upstream proxy username: "), "password": getpass.getpass("Upstream proxy password (hidden): ")}
        from claude_protect.upstream import request_bytes
        request_bytes("example.com:443", **credentials)
    created_proxy_user = False
    proxy_user = None
    if args.upstream_ip:
        try:
            proxy_user = pwd.getpwnam(PROXY_USER)
            if proxy_user.pw_uid >= 1000 or proxy_user.pw_uid == 0 or proxy_user.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin"):
                parser.error("existing proxy service account is not a locked system user")
        except KeyError:
            command("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", PROXY_USER)
            created_proxy_user = True
            proxy_user = pwd.getpwnam(PROXY_USER)
        values["proxy_uid"] = proxy_user.pw_uid
        if grp.getgrnam(PROXY_USER).gr_gid != proxy_user.pw_gid:
            parser.error("proxy service user/group do not match")
    config = Config(**values)
    source = ROOT / "lib/claude_protect"
    library = Path("/usr/local/lib/claude-protect/claude_protect")
    library.mkdir(parents=True, exist_ok=True)
    for file in source.glob("*.py"):
        write(library / file.name, file.read_text())
    assets = source / "assets"
    if assets.is_dir():
        shutil.copytree(assets, library / "assets", dirs_exist_ok=True)
    for file in (ROOT / "bin").iterdir():
        target = Path("/usr/local/bin") if file.name == "claude-protect" else Path("/usr/local/libexec")
        write(target / file.name, file.read_text(), 0o755)
    write(CONFIG, json.dumps(config.to_dict(), indent=2) + "\n")
    write("/etc/claude-protect/install-state.json", json.dumps({"created_proxy_user": created_proxy_user}) + "\n", 0o600)
    if proxy_user:
        secrets = "/etc/claude-protect/upstream-credentials.json"
        write(secrets, json.dumps(credentials) + "\n", 0o640)
        os.chown(secrets, 0, proxy_user.pw_gid)
    write("/etc/claude-protect/resolv.conf", "# Private mount only; the host resolver is untouched.\nnameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
    resolver = Path("/etc/claude-protect/resolver")
    resolver.mkdir(mode=0o755, exist_ok=True)
    for name in ("stub-resolv.conf", "resolv.conf"):
        os.link("/etc/claude-protect/resolv.conf", resolver / name)
    Path("/etc/claude-protect/empty").mkdir(mode=0o755, exist_ok=True)
    write("/etc/claude-protect/blocked", "", 0o000)
    sudoers = f"{args.user} ALL=(root) NOPASSWD: /usr/local/libexec/claude-protect-helper run *\n"
    sudoers += "Defaults!/usr/local/libexec/claude-protect-helper env_keep += \"DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_SESSION_TYPE XDG_CURRENT_DESKTOP LANG LANGUAGE LC_ALL LC_CTYPE LC_MESSAGES LC_TIME LC_NUMERIC LC_COLLATE\"\n"
    pending = Path("/etc/claude-protect/sudoers.pending")
    write(pending, sudoers, 0o440)
    command("/usr/sbin/visudo", "-cf", str(pending))
    pending.replace("/etc/sudoers.d/claude-protect")
    share = Path("/usr/local/share/claude-protect")
    share.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "LICENSE", "NOTICE.md"):
        write(share / name, (ROOT / name).read_text())
    write(share / "uninstall.py", (ROOT / "scripts/uninstall.py").read_text())
    for file in (ROOT / "docs").glob("*.md"):
        write(share / "docs" / file.name, file.read_text())
    shutil.copyfile(vsix, share / "claude-protect.vsix")
    os.chmod(share / "claude-protect.vsix", 0o644)
    network = """[Unit]
Description=Claude Protect isolated network
After=network.target
Before=claude-protect-relay.service claude-protect-status.service claude-protect-upstream.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/claude-protect-helper setup
ExecStop=/usr/local/libexec/claude-protect-helper teardown

[Install]
WantedBy=multi-user.target
"""
    relay = """[Unit]
Description=Claude Protect opaque proxy relay
Requires=claude-protect-network.service
After=claude-protect-network.service

[Service]
ExecStart=/usr/local/libexec/claude-protect-relay
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
"""
    status = """[Unit]
Description=Claude Protect read-only kernel status
Requires=claude-protect-network.service
After=claude-protect-network.service

[Service]
ExecStart=/usr/local/libexec/claude-protect-status
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/claude-protect
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
"""
    for name, content in (("network", network), ("relay", relay), ("status", status)):
        write(f"/etc/systemd/system/claude-protect-{name}.service", content)
    write("/usr/local/lib/systemd/user/claude-protect-keyring.service", user_unit())
    services = ["claude-protect-network.service", "claude-protect-relay.service", "claude-protect-status.service"]
    if proxy_user:
        write("/etc/systemd/system/claude-protect-upstream.service", """[Unit]
Description=Claude Protect fixed TLS upstream CONNECT proxy
Requires=claude-protect-network.service
After=claude-protect-network.service network-online.target
Before=claude-protect-relay.service

[Service]
User=claude-protect-proxy
Group=claude-protect-proxy
ExecStart=/usr/local/libexec/claude-protect-upstream
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
InaccessiblePaths=-/run/dbus -/run/systemd/resolve -/run/nscd -/run/user
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_UNIX
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
""")
        services.insert(1, "claude-protect-upstream.service")
    icon = library / "assets" / "claude-protect.png"
    icon_name = str(icon) if icon.is_file() else "security-high"
    write("/usr/local/share/applications/claude-protect.desktop", f"""[Desktop Entry]
Type=Application
Name=Claude Protect — VS Code
Comment=Open a dedicated VS Code window with restricted proxy egress
Exec=/usr/local/bin/claude-protect launch %f
Icon={icon_name}
Terminal=false
Categories=Development;
""")
    write("/usr/local/share/applications/claude-protect-browser.desktop", f"""[Desktop Entry]
Type=Application
Name=Claude Protect — Browser
Name[zh_CN]=Claude Protect — 受保护浏览器
Comment=Open Claude in a dedicated browser with restricted proxy egress
Exec=/usr/local/bin/claude-protect browser https://claude.ai/
Icon={icon_name}
Terminal=false
Categories=Network;WebBrowser;
""")
    command("/usr/bin/systemctl", "daemon-reload")
    command("/usr/bin/systemctl", "enable", "--now", *services)
    print("Installed. As the desktop user, run:")
    print("  claude-protect install-plugin")
    print("  claude-protect install-official")
    print("  claude-protect launch /absolute/path/to/project")
    print("  claude-protect browser https://claude.ai/")
    print("No Claude account credentials were read or copied.")
    print("Managed upstream enabled." if proxy_user else "External proxy mode: only application isolation is verified; upstream DNS/egress is unmanaged.")
    print("Unlock your desktop keyring before starting protected GUI applications.")


if __name__ == "__main__":
    main()
