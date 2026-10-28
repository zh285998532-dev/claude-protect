"""Same-namespace browser and scoped vscode:// handler; no global MIME changes."""
import os
from pathlib import Path
import pwd
import sys
from urllib.parse import urlsplit


def validate_url(url):
    if len(url) > 32768 or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("invalid URL")
    parsed = urlsplit(url)
    if parsed.scheme not in ("https", "http", "vscode") or not parsed.hostname:
        raise ValueError("only HTTP(S) and vscode callback URLs are accepted")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credential-bearing URLs are not accepted")
    if parsed.scheme == "vscode" and parsed.hostname.lower() != "anthropic.claude-code":
        raise ValueError("only the official Claude Code vscode callback is accepted")
    return url


def main(argv=None):
    from .cli import read_status
    from .config import load_config
    from .helper import profile_paths, app_environment
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        raise ValueError("open exactly one URL")
    url = validate_url(argv[0])
    if not read_status().get("session_isolated"):
        raise RuntimeError("browser/callback must run inside the verified protected environment")
    from .keyring import verify
    verify()
    config = load_config()
    user = pwd.getpwuid(os.getuid())
    profile, extensions = profile_paths(user)
    if urlsplit(url).scheme == "vscode":
        command = [config.code, "--user-data-dir", str(profile), "--extensions-dir", str(extensions),
                   "--password-store=gnome-libsecret", "--open-url", url]
    else:
        chrome = Path("/usr/bin/google-chrome")
        if not chrome.exists():
            raise RuntimeError("protected browser requires the official Google Chrome .deb; install it or use a supported official manual authorization flow")
        resolved = chrome.resolve()
        info = resolved.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or "/snap/" in str(resolved):
            raise RuntimeError("browser must be the root-managed .deb build")
        # Never silently reuse/import the v0.1 profile whose actual key store
        # was not checked. Existing files remain available for manual recovery.
        browser_profile = profile.parent / "browser-v2"
        browser_profile.mkdir(mode=0o700, exist_ok=True)
        # Refuse to reuse a browser profile accidentally opened outside isolation.
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                args = (entry / "cmdline").read_bytes().split(b"\0")
                marker = os.fsencode(str(browser_profile))
                selected = any(arg == b"--user-data-dir=" + marker or
                               (arg == b"--user-data-dir" and index + 1 < len(args) and args[index + 1] == marker)
                               for index, arg in enumerate(args))
                if selected:
                    if (entry / "ns/net").stat().st_ino != os.stat("/proc/self/ns/net").st_ino:
                        raise RuntimeError("protected browser profile is active outside isolation; close it first")
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        command = [str(chrome), "--user-data-dir=" + str(browser_profile),
                   "--proxy-server=" + config.proxy_url, "--password-store=gnome-libsecret",
                   "--no-first-run", "--new-window", url]
    os.execve(command[0], command, app_environment(config, user, os.environ))
