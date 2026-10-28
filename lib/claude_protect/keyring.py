"""Filtered Secret Service access. No secret values are requested or logged."""
import os
from pathlib import Path
import re
import stat
import subprocess

SERVICE = "claude-protect-keyring.service"
DESTINATION = "org.freedesktop.secrets"
ROOT_PATH = "/org/freedesktop/secrets"


def socket_path(uid=None):
    return Path(f"/run/user/{os.getuid() if uid is None else uid}/claude-protect-keyring/bus")


def bus_address(uid=None):
    return "unix:path=" + str(socket_path(uid))


def proxy_arguments(runtime="%t"):
    # No --talk wildcard, portal, resolver, systemd, or general session-bus access.
    args = ["/usr/bin/xdg-dbus-proxy", f"unix:path={runtime}/bus", f"{runtime}/claude-protect-keyring/bus", "--filter"]
    methods = {
        "Service": ("OpenSession", "ReadAlias", "SearchItems", "Unlock", "Lock", "GetSecrets"),
        "Collection": ("SearchItems", "CreateItem"),
        "Item": ("GetSecret", "SetSecret", "Delete"),
        "Session": ("Close",),
        "Prompt": ("Prompt", "Dismiss"),
    }
    for interface, allowed_methods in methods.items():
        path = ROOT_PATH if interface == "Service" else ROOT_PATH + "/*"
        for method in allowed_methods:
            args.append(f"--call={DESTINATION}=org.freedesktop.Secret.{interface}.{method}@{path}")
    args.extend([
        f"--call={DESTINATION}=org.freedesktop.DBus.Introspectable.Introspect@{ROOT_PATH}",
        f"--call={DESTINATION}=org.freedesktop.DBus.Properties.Get@{ROOT_PATH}/*",
        f"--call={DESTINATION}=org.freedesktop.DBus.Properties.GetAll@{ROOT_PATH}/*",
        f"--call={DESTINATION}=org.freedesktop.DBus.Properties.Set@{ROOT_PATH}/*",
        f"--call={DESTINATION}=org.freedesktop.DBus.Introspectable.Introspect@{ROOT_PATH}/*",
        f"--broadcast={DESTINATION}=org.freedesktop.Secret.*@{ROOT_PATH}/*",
    ])
    return args


def user_unit():
    return """[Unit]
Description=Claude Protect filtered Secret Service channel
After=dbus.socket
Requires=dbus.socket

[Service]
Type=exec
RuntimeDirectory=claude-protect-keyring
RuntimeDirectoryMode=0700
UMask=0077
ExecStart=""" + " ".join(proxy_arguments()) + """
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
Restart=on-failure
RestartSec=1

[Install]
WantedBy=default.target
"""


def _call(object_path, method, *arguments):
    command = ["/usr/bin/gdbus", "call", "--address", bus_address(), "--dest", DESTINATION,
               "--object-path", object_path, "--method", method, *arguments]
    result = subprocess.run(command, capture_output=True, text=True, timeout=6, check=False,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    if result.returncode:
        # Do not surface remote replies or any secret-service values in errors.
        raise RuntimeError("filtered Secret Service is unavailable; unlock the desktop keyring and check the user service")
    return result.stdout.strip()


def verify():
    import ctypes
    try:
        ctypes.CDLL("libsecret-1.so.0")
    except OSError:
        raise RuntimeError("libsecret is unavailable; install libsecret-1-0 before starting protected applications") from None
    path = socket_path()
    try:
        info = path.lstat()
        directory = path.parent.lstat()
    except OSError:
        raise RuntimeError("filtered keyring socket is missing; start Claude Protect from the normal desktop session") from None
    if (not stat.S_ISSOCK(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
            or directory.st_uid != os.getuid() or directory.st_mode & 0o077 or path.parent.is_symlink()):
        raise RuntimeError("unsafe filtered keyring socket ownership or permissions")
    reply = _call(ROOT_PATH, "org.freedesktop.Secret.Service.ReadAlias", "default")
    match = re.fullmatch(r"\(objectpath '(/org/freedesktop/secrets/collection/[A-Za-z0-9_/]+)',\)", reply)
    if not match:
        raise RuntimeError("no default desktop keyring collection; create and unlock it in the desktop password manager")
    locked = _call(match.group(1), "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Locked")
    if locked != "(<false>,)":
        raise RuntimeError("desktop keyring is locked; unlock it before starting protected applications")
    return {"available": True, "default_collection_unlocked": True, "filtered_bus": True,
            "requested_backend": "gnome-libsecret", "actual_browser_backend": "not_observed",
            "collection_encryption_at_rest": "not_observed"}


def ensure():
    # This is run by the unprivileged launcher BEFORE entering the namespace.
    reloaded = subprocess.run(["/usr/bin/systemctl", "--user", "daemon-reload"], capture_output=True, timeout=12, check=False)
    if reloaded.returncode:
        raise RuntimeError("could not contact the desktop user service manager")
    result = subprocess.run(["/usr/bin/systemctl", "--user", "start", SERVICE], capture_output=True,
                            timeout=12, check=False)
    if result.returncode:
        raise RuntimeError("could not start the filtered keyring user service; use a logged-in Ubuntu desktop session")
    import time
    for _ in range(30):
        if socket_path().exists():
            return verify()
        time.sleep(0.05)
    raise RuntimeError("filtered keyring proxy did not become ready")
