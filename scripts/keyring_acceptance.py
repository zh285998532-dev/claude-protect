#!/usr/bin/env python3
"""Run in an Ubuntu desktop session; no secret/password/token values are read."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
from claude_protect.keyring import ensure, bus_address


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("run as the logged-in Ubuntu desktop user, without sudo")
    report = ensure()
    def call(destination, path, method, *params):
        return subprocess.run(["/usr/bin/gdbus", "call", "--address", bus_address(), "--dest", destination,
                               "--object-path", path, "--method", method, *params], capture_output=True,
                              text=True, timeout=6, check=False)
    visible = call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus.ListNames")
    if visible.returncode:
        raise RuntimeError("filtered bus could not be queried")
    report["host_services_hidden"] = not any(name in visible.stdout for name in
        ("org.freedesktop.systemd1", "org.freedesktop.resolve1", "org.freedesktop.portal.Desktop", "org.gnome.Shell"))
    # These requests must fail. Their error payloads are deliberately discarded.
    checks = [
        ("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager.GetUnit", "dbus.service"),
        ("org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.DBus.Introspectable.Introspect"),
        ("org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.DBus.Introspectable.Introspect"),
    ]
    report["non_secret_calls_denied"] = all(call(*check).returncode != 0 for check in checks)
    report["passed"] = report["host_services_hidden"] and report["non_secret_calls_denied"]
    report["scope"] = "Secret Service availability and filtered D-Bus paths; not Chrome backend/at-rest encryption proof"
    print(json.dumps(report, indent=None if args.json else 2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError):
        print("Keyring acceptance failed. Unlock the desktop keyring and inspect the user service; no secret values were exported.", file=sys.stderr)
        raise SystemExit(1)
