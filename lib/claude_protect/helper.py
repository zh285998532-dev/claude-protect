"""Privileged entry point; only fixed commands run before privileges are dropped."""
import argparse
import json
import os
from pathlib import Path
import pwd
import stat
import sys

from .config import CONFIG, HELPER, NAMESPACE, load_config
from . import kernel

LOCALE_KEYS = ("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_TIME", "LC_NUMERIC", "LC_COLLATE")


def caller(config):
    # sudo supplies this value itself; clients cannot select the target UID.
    raw = os.environ.get("SUDO_UID")
    if raw is None or int(raw) != config.uid:
        raise RuntimeError("launch is restricted to the user selected at installation; use the non-root claude-protect command")
    return pwd.getpwuid(config.uid)


def profile_paths(user):
    root = Path(user.pw_dir) / ".local/share/claude-protect"
    return root / "code", root / "extensions"


def app_environment(config, user, inherited):
    # Never forward LD_*, PYTHON*, credentials, endpoint overrides or TLS bypasses.
    env = {"HOME": user.pw_dir, "USER": user.pw_name, "LOGNAME": user.pw_name,
           "PATH": "/usr/local/bin:/usr/bin:/bin",
           "XDG_RUNTIME_DIR": f"/run/user/{user.pw_uid}",
           "HTTP_PROXY": config.proxy_url, "HTTPS_PROXY": config.proxy_url,
           "http_proxy": config.proxy_url, "https_proxy": config.proxy_url,
           "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1",
           "CLAUDE_PROTECT_SESSION": "1",
           "BROWSER": "/usr/local/libexec/claude-protect-open",
           "XDG_CONFIG_HOME": str(Path(user.pw_dir) / ".local/share/claude-protect/xdg-config"),
           "XDG_DATA_HOME": str(Path(user.pw_dir) / ".local/share/claude-protect/xdg-data")}
    from .keyring import bus_address
    env["DBUS_SESSION_BUS_ADDRESS"] = bus_address(user.pw_uid)
    # Preserve natural user locale; kernel tool output still uses ROOT_ENV.
    for key in LOCALE_KEYS:
        if inherited.get(key):
            env[key] = inherited[key]
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP"):
        if inherited.get(key):
            env[key] = inherited[key]
    return env


def check_code_binary(config):
    # /usr/bin/code is normally a root-owned symlink to the Microsoft .deb script.
    path = Path(config.code)
    for candidate in (path, path.resolve()):
        info = candidate.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise RuntimeError("VS Code launcher must be root-owned and not group/world writable")
    if "/snap/" in str(path.resolve()):
        raise RuntimeError("Snap VS Code is unsupported; install Microsoft's official .deb")


def check_outside_profile(user, expected_inode):
    profile, _ = profile_paths(user)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != user.pw_uid:
                continue
            args = (entry / "cmdline").read_bytes().split(b"\0")
            marker = os.fsencode(str(profile))
            selected = any(arg == b"--user-data-dir=" + marker or
                           (arg == b"--user-data-dir" and index + 1 < len(args) and args[index + 1] == marker)
                           for index, arg in enumerate(args))
            if selected and (entry / "ns/net").stat().st_ino != expected_inode:
                raise RuntimeError("the protected VS Code profile is already running outside isolation; close that window first")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


def application_command(config, user, mode, argument=None):
    profile, extensions = profile_paths(user)
    common = [config.code, "--user-data-dir", str(profile), "--extensions-dir", str(extensions)]
    if mode == "code":
        command = common + ["--new-window", "--password-store=gnome-libsecret", "--proxy-server=" + config.proxy_url]
        if argument:
            folder = Path(argument)
            if not folder.is_absolute() or not folder.is_dir():
                raise ValueError("workspace must be an existing absolute directory")
            command.append(str(folder))
        return command
    if mode == "install-official":
        return common + ["--install-extension", "anthropic.claude-code"]
    if mode == "install-plugin":
        return common + ["--install-extension", "/usr/local/share/claude-protect/claude-protect.vsix"]
    if mode == "probe":
        return ["/usr/bin/python3", "-I", "/usr/local/libexec/claude-protect-probe"]
    if mode == "egress":
        return ["/usr/bin/python3", "-I", "/usr/local/libexec/claude-protect-probe", "--egress"]
    if mode == "stream-check":
        return ["/usr/bin/python3", "-I", "/usr/local/libexec/claude-protect-probe", "--stream-check"]
    if mode == "browser":
        from .browser import validate_url
        return ["/usr/local/libexec/claude-protect-open", validate_url(argument or "https://claude.ai/")]
    raise ValueError("unsupported launch mode")


def enter(config, mode, argument):
    user = caller(config)
    checked = kernel.status(config)
    if not checked["kernel_ok"]:
        raise RuntimeError("kernel protection failed verification; refusing to launch")
    if mode not in ("probe", "egress", "stream-check"):
        check_code_binary(config)
        check_outside_profile(user, checked["namespace_inode"])
    # The inner helper rechecks policy and drops ALL capabilities before app exec.
    command = kernel.ns_command("/usr/bin/unshare", "--mount", "--fork", "--propagation", "private",
                                HELPER, "inner", mode)
    if argument:
        command.append(argument)
    os.execve(command[0], command, {**kernel.ROOT_ENV, **{
        key: os.environ[key] for key in ("SUDO_UID", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
                                         "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", *LOCALE_KEYS) if key in os.environ}})


def isolate_host_resolver(user):
    # ip netns alone does not stop nss-resolve delegating queries over host AF_UNIX.
    # This is a private mount namespace; host files and the host resolver are untouched.
    # Ubuntu commonly symlinks resolv.conf into /run/systemd/resolve. Keep private
    # stub files there while hiding the resolver socket; masking it with an empty
    # directory would leave that symlink dangling.
    if Path("/run/systemd/resolve").exists():
        kernel.run([kernel.TOOLS["mount"], "--bind", "/etc/claude-protect/resolver", "/run/systemd/resolve"])
    kernel.run([kernel.TOOLS["mount"], "--bind", "/etc/claude-protect/resolv.conf", "/etc/resolv.conf"])
    # Mask resolver/system-bus and common daemon sockets that can relay host traffic.
    directories = ["/run/dbus", "/run/nscd", "/var/cache/nscd",
                   "/run/podman", f"/run/user/{user.pw_uid}/podman"]
    sockets = ["/run/docker.sock", f"/run/user/{user.pw_uid}/docker.sock",
               f"/run/user/{user.pw_uid}/bus"]
    for target in directories:
        if Path(target).exists():
            kernel.run([kernel.TOOLS["mount"], "--bind", "/etc/claude-protect/empty", target])
    for target in sockets:
        if Path(target).exists():
            kernel.run([kernel.TOOLS["mount"], "--bind", "/etc/claude-protect/blocked", target])


def inner(config, mode, argument):
    user = caller(config)
    status = kernel.status(config)
    if not status["kernel_ok"] or os.stat("/proc/self/ns/net").st_ino != status["namespace_inode"]:
        raise RuntimeError("inner launcher is not inside the verified network namespace")
    # inner is not permitted by sudoers and cannot be invoked through the public CLI.
    # It must already be in a separate mount namespace made by enter().
    if os.stat("/proc/self/ns/mnt").st_ino == os.stat("/proc/1/ns/mnt").st_ino:
        raise RuntimeError("refusing to change mounts in the host mount namespace")
    isolate_host_resolver(user)
    command = ["/usr/bin/setpriv", "--reuid", str(user.pw_uid), "--regid", str(user.pw_gid),
               "--init-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
               "--no-new-privs", "--", "/usr/local/libexec/claude-protect-session", mode]
    if argument:
        command.append(argument)
    os.chdir(user.pw_dir)
    os.execve(command[0], command, app_environment(config, user, os.environ))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Root-owned Claude Protect helper")
    parser.add_argument("action", choices=("setup", "teardown", "status", "run", "inner"))
    parser.add_argument("mode", nargs="?", choices=("code", "install-official", "install-plugin", "probe", "egress", "stream-check", "browser"))
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("helper requires Linux and root")
    config = load_config(CONFIG)
    if args.action in ("run", "inner"):
        if not args.mode or (args.argument and args.mode not in ("code", "browser")):
            parser.error("invalid launch arguments")
        (enter if args.action == "run" else inner)(config, args.mode, args.argument)
    else:
        if args.mode or args.argument:
            parser.error("unexpected arguments")
        if args.action == "status":
            caller(config)
            print(json.dumps(kernel.status(config)))
        else:
            if os.environ.get("SUDO_UID") and int(os.environ["SUDO_UID"]) != config.uid:
                raise RuntimeError("wrong installing user")
            (kernel.setup if args.action == "setup" else kernel.teardown)(config)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError) as error:
        print(f"Claude Protect: {error}", file=sys.stderr)
        raise SystemExit(1)
