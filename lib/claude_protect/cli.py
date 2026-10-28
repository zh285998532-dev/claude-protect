"""Unprivileged user commands. Never reads account tokens or proxy passwords."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys

from . import __version__
from .config import HELPER, load_config
from .helper import app_environment, application_command, profile_paths

CLI_PATH = "/usr/local/bin/claude-protect"


def read_status():
    path = Path("/run/claude-protect/status.sock")
    for part in [path, *path.parents]:
        info = part.lstat()
        if info.st_uid != 0 or part.is_symlink() or (part != path and info.st_mode & 0o022):
            raise RuntimeError("untrusted status socket path")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(8)
        client.connect(str(path))
        peer_uid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        if peer_uid != 0:
            raise RuntimeError("status server is not root-owned")
        data = bytearray()
        while not data.endswith(b"\n"):
            block = client.recv(4096)
            if not block:
                break
            data.extend(block)
            if len(data) > 65536:
                raise RuntimeError("oversized status reply")
    result = json.loads(data)
    inode = os.stat("/proc/self/ns/net").st_ino
    def same_mount(left, right):
        try:
            return os.path.samefile(left, right)
        except OSError:
            return False
    process_status = Path("/proc/self/status").read_text()
    fields = dict(line.split(":", 1) for line in process_status.splitlines() if ":" in line)
    runtime = {
        "namespace_identity": result.get("namespace_inode") == inode,
        "resolver_mount": same_mount("/etc/resolv.conf", "/etc/claude-protect/resolv.conf"),
        "host_resolver_hidden": all(same_mount(target, "/etc/claude-protect/empty")
                                    for target in ("/run/dbus", "/run/nscd", "/var/cache/nscd")
                                    if Path(target).exists()),
        "resolved_socket_hidden": not Path("/run/systemd/resolve").exists() or
                                  same_mount("/run/systemd/resolve", "/etc/claude-protect/resolver"),
        "no_new_privileges": fields.get("NoNewPrivs", "").strip() == "1",
        "no_capabilities": int(fields.get("CapBnd", "1").strip(), 16) == 0,
        "configured_user": result.get("uid") == os.getuid(),
    }
    result["runtime_checks"] = runtime
    result["session_isolated"] = bool(result.get("kernel_ok") and all(runtime.values()))
    result["current_namespace_inode"] = inode
    return result


def prepare_profile(config):
    user = pwd.getpwuid(os.getuid())
    if user.pw_uid != config.uid:
        raise RuntimeError("this installation belongs to a different user")
    profile, extensions = profile_paths(user)
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    extensions.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings = profile / "User/settings.json"
    settings.parent.mkdir(mode=0o700, exist_ok=True)
    # Never rewrite an existing JSONC settings file or copy account/browser state.
    if not settings.exists():
        env = [{"name": name, "value": config.proxy_url}
               for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")]
        content = {"http.proxy": config.proxy_url, "http.proxySupport": "override",
                   "claudeCode.environmentVariables": env,
                   "security.workspace.trust.enabled": True}
        with settings.open("x") as output:
            json.dump(content, output, indent=2)
            output.write("\n")
    xdg = profile.parent
    applications = xdg / "xdg-data/applications"
    applications.mkdir(parents=True, exist_ok=True)
    handler = applications / "claude-protect-url.desktop"
    if not handler.exists():
        handler.write_text("[Desktop Entry]\nType=Application\nName=Claude Protect URL\n"
                           "Exec=/usr/local/libexec/claude-protect-open %u\nNoDisplay=true\n"
                           "MimeType=x-scheme-handler/http;x-scheme-handler/https;x-scheme-handler/vscode;\n")
    config_dir = xdg / "xdg-config"
    config_dir.mkdir(parents=True, exist_ok=True)
    mimeapps = config_dir / "mimeapps.list"
    if not mimeapps.exists():
        mimeapps.write_text("[Default Applications]\n"
                            "x-scheme-handler/http=claude-protect-url.desktop\n"
                            "x-scheme-handler/https=claude-protect-url.desktop\n"
                            "x-scheme-handler/vscode=claude-protect-url.desktop\n")


def launch(config, mode, argument=None):
    prepare_profile(config)
    current = read_status()
    if not current.get("kernel_ok"):
        raise RuntimeError("protection is not ready; run 'claude-protect status' and inspect system services")
    if mode in ("code", "browser"):
        from .keyring import ensure, verify
        (verify if current.get("session_isolated") else ensure)()
    if current.get("session_isolated"):
        user = pwd.getpwuid(os.getuid())
        command = application_command(config, user, mode, argument)
        os.execve(command[0], command, app_environment(config, user, os.environ))
    command = ["/usr/bin/sudo", "-n", HELPER, "run", mode]
    if argument:
        command.append(argument)
    os.execv(command[0], command)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Claude Protect — isolated Ubuntu VS Code, not an account-ban guarantee")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    opening = sub.add_parser("launch", help="open a dedicated protected VS Code window")
    opening.add_argument("folder", nargs="?")
    checking = sub.add_parser("status", help="inspect kernel policy and this process's namespace")
    checking.add_argument("--json", action="store_true")
    sub.add_parser("probe", help="explicit live tests; contacts example.com through the proxy")
    sub.add_parser("egress", help="opt-in: observe public exit via two HTTPS requests to ipify inside isolation")
    sub.add_parser("stream-check", help="opt-in: bounded 20-second httpbin stream and connection reuse sample inside isolation")
    sub.add_parser("audit", help="offline audit of this process's allowlisted environment; never prints credentials")
    sub.add_parser("upstream-check", help="opt-in: inspect external Clash/Mihomo, Claude TLS, DNS settings and isolated exit")
    sub.add_parser("install-official", help="install the official Claude Code extension into the protected profile")
    sub.add_parser("install-plugin", help="install this companion extension into the protected profile")
    browser = sub.add_parser("browser", help="open a protected Google Chrome .deb browser; no profile/identity spoofing")
    browser.add_argument("url", nargs="?", default="https://claude.ai/")
    sub.add_parser("guide", help="print the installed guide path")
    keyring = sub.add_parser("keyring-status", help="check filtered, unlocked Secret Service without reading secrets")
    keyring.add_argument("--json", action="store_true")
    keyring.add_argument("--start", action="store_true", help="explicitly start the filtered user service before checking")
    gui = sub.add_parser("gui", help="open the optional PySide6 desktop panel with the current Python environment")
    gui.add_argument("--demo", action="store_true", help="preview only; no system actions")
    args = parser.parse_args(argv)
    if args.command == "audit":
        from .diagnostics import audit_environment
        print(json.dumps(audit_environment(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "upstream-check":
        from .external_audit import main as upstream_main
        return upstream_main()
    if args.command == "gui":
        try:
            from .gui import main as gui_main
        except ModuleNotFoundError as error:
            if error.name != "PySide6":
                raise
            parser.error("PySide6 is missing in this Python environment; see docs/GUI.md")
        return gui_main(["--demo"] if args.demo else [])
    if sys.platform != "linux":
        parser.error("runtime commands support Ubuntu/Linux only; build/tests are cross-platform")
    if args.command == "guide":
        print("/usr/local/share/claude-protect/README.md")
        return 0
    if args.command == "keyring-status":
        from .keyring import ensure, verify
        print(json.dumps((ensure if args.start else verify)(), indent=None if args.json else 2))
        return 0
    if args.command == "status":
        result = read_status()
        if args.json:
            print(json.dumps(result))
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
            if not result["session_isolated"]:
                print("This window/process is outside isolation. Use claude-protect launch.")
        return 0 if result.get("kernel_ok") else 1
    config = load_config()
    mapping = {"launch": "code", "probe": "probe", "egress": "egress", "stream-check": "stream-check", "install-official": "install-official",
               "install-plugin": "install-plugin", "browser": "browser"}
    argument = str(Path(args.folder).expanduser().resolve()) if args.command == "launch" and args.folder else None
    if args.command == "browser":
        argument = args.url
    launch(config, mapping[args.command], argument)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Claude Protect: {error}", file=sys.stderr)
        raise SystemExit(1)
