"""Local, credential-free observations and allowlisted diagnostic reports."""
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

from . import __version__

EGRESS_TARGET = "https://api.ipify.org?format=json"
STREAM_TARGET = "https://httpbin.org/drip?duration=20&numbytes=10&delay=0&code=200"
PROXY_KEYS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY")
FINDING_IDS = {"malformed_proxy", "socks_proxy", "proxy_case_conflict", "proxy_bypass", "provider_override",
               "api_key_present", "tls_verification_disabled", "no_environment_findings"}


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _proxy(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https", "socks5", "socks5h") or not parsed.hostname:
            raise ValueError()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 1080 if parsed.scheme.startswith("socks") else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        if any(ord(ch) < 32 for ch in value):
            raise ValueError()
        return (parsed.scheme, parsed.hostname.lower(), port), parsed.username is not None or parsed.password is not None
    except ValueError:
        return None, False


def audit_environment(environment=None):
    """Inspect only this process's allowlisted environment; never return raw URLs."""
    environment = os.environ if environment is None else environment
    findings = []

    def note(identifier, level, message):
        findings.append({"id": identifier, "level": level, "message": message})

    endpoints = {}
    configured = []
    for key in PROXY_KEYS:
        value = environment.get(key, "")
        if not value:
            continue
        endpoint, authenticated = _proxy(value)
        endpoints[key] = endpoint
        configured.append({"name": key, "valid": endpoint is not None,
                           "scheme": endpoint[0] if endpoint else "invalid", "authentication_present": authenticated})
    if any(endpoint is None for endpoint in endpoints.values()):
        note("malformed_proxy", "attention", "存在格式无效的代理环境变量；未记录原始值。")
    if any(item["scheme"].startswith("socks") for item in configured):
        note("socks_proxy", "attention", "发现 SOCKS 代理变量；官方 Claude Code 的 HTTP(S) 代理入口需另外核对。")
    if any(lower in endpoints and upper in endpoints and endpoints[lower] != endpoints[upper]
           for lower, upper in (("https_proxy", "HTTPS_PROXY"), ("http_proxy", "HTTP_PROXY"))):
        note("proxy_case_conflict", "attention", "大小写代理变量指向不同端点，可能因客户端优先级不同而使用不同路径。")
    bypass = " ".join(environment.get(key, "") for key in ("NO_PROXY", "no_proxy"))
    tokens = [token for token in re.split(r"[\s,]+", bypass) if token]
    loopback = {"localhost", "127.0.0.1", "::1", "[::1]", "127.0.0.0/8", "localhost.localdomain"}
    if any(token.lower() not in loopback for token in tokens):
        note("proxy_bypass", "attention", "NO_PROXY 包含回环地址以外的旁路设置；这不等于专用窗口已能绕过内核限制。")
    if environment.get("ANTHROPIC_BASE_URL"):
        note("provider_override", "attention", "存在 ANTHROPIC_BASE_URL；请确认是否有意使用自定义 API 端点。网络代理与 API 中转是两层。")
    if environment.get("ANTHROPIC_API_KEY"):
        note("api_key_present", "attention", "当前进程环境存在 API Key；官方客户端读取该值时可能使用 API 计费，而非 Pro / Max 额度。不会展示或保存密钥值。")
    if environment.get("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        note("tls_verification_disabled", "attention", "当前环境请求关闭 Node TLS 证书验证；请检查该设置。")
    if not findings:
        note("no_environment_findings", "info", "本次白名单环境检查未发现上述配置问题；尚未检查客户端设置文件。")
    locale_value = environment.get("LANG", "")
    locale_value = locale_value if re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", locale_value) else "not_observed"
    return {"schema": 1, "checked_at": timestamp(), "scope": "current_process_environment_only",
            "findings": findings, "proxy_variables": configured,
            "environment": {"locale": locale_value, "timezone_names": list(time.tzname)},
            "not_checked": ["vscode_settings", "project_settings", "running_claude_environment", "browser_fingerprint"],
            "note": "面板 / 命令所在进程的环境快照。启动器会重建应用环境；本结果不证明运行中的 Claude 设置，也不评估封号概率。"}


def public_ip(value):
    if not isinstance(value, str):
        raise ValueError("expected an IP string")
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError("expected a public IP")
    return str(address)


def mask_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return "not_observed"
    if address.version == 4:
        return ".".join(str(address).split(".")[:3]) + ".x"
    return str(ipaddress.ip_network(f"{address}/48", strict=False))


def _check_file(descriptor):
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
        raise ValueError("diagnostic file must be private, user-owned and not hard-linked")


class History:
    """Up to 30 local samples; never a cloud service or a background poller."""
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else Path.home() / ".local/share/claude-protect/diagnostics/egress-history.json"

    def _directory(self, create=False):
        if create:
            self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("diagnostic history directory must be private and user-owned")

    def read(self):
        try:
            self._directory()
            descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return []
        with os.fdopen(descriptor, "rb") as stream:
            _check_file(stream.fileno())
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("oversized diagnostic history")
        data = json.loads(raw)
        if not isinstance(data, list) or len(data) > 30:
            raise ValueError("invalid diagnostic history")
        for entry in data:
            if (not isinstance(entry, dict) or set(entry) != {"checked_at", "target", "policy_context", "ips", "stable_during_sample"}
                    or entry["target"] != EGRESS_TARGET
                    or not isinstance(entry["policy_context"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", entry["policy_context"])
                    or type(entry["stable_during_sample"]) is not bool
                    or not isinstance(entry["ips"], list) or not 1 <= len(entry["ips"]) <= 2):
                raise ValueError("invalid diagnostic history entry")
            if not isinstance(entry["checked_at"], str):
                raise ValueError("invalid observation timestamp")
            datetime.fromisoformat(entry["checked_at"])
            for address in entry["ips"]:
                public_ip(address)
        return data

    def record(self, result):
        if (result.get("status") != "complete" or result.get("target") != EGRESS_TARGET
                or not re.fullmatch(r"[0-9a-f]{64}", result.get("policy_context", ""))
                or type(result.get("stable_during_sample")) is not bool):
            raise ValueError("only complete observations can enter history")
        ips = sorted({public_ip(ip) for ip in result.get("observed_ips", [])})
        if not 1 <= len(ips) <= 2:
            raise ValueError("invalid observed IP set")
        datetime.fromisoformat(result["checked_at"])
        self._directory(create=True)
        lock = os.open(self.path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(lock, "a+b") as lock_file:
            import fcntl
            _check_file(lock_file.fileno())
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            entries = self.read()
            previous = next((entry for entry in reversed(entries) if entry["policy_context"] == result["policy_context"]), None)
            entry = {"checked_at": result["checked_at"], "target": EGRESS_TARGET,
                     "policy_context": result["policy_context"], "ips": ips,
                     "stable_during_sample": result["stable_during_sample"]}
            entries = (entries + [entry])[-30:]
            temp = self.path.with_name(f".egress-{os.getpid()}-{time.monotonic_ns()}.tmp")
            try:
                descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "w") as stream:
                    json.dump(entries, stream, ensure_ascii=False, indent=2)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, self.path)
            finally:
                temp.unlink(missing_ok=True)
        return {"changed_since_previous": ips != previous["ips"] if previous else None,
                "previous_ips": previous["ips"] if previous else [], "records": entries}

    def clear(self):
        self.read()  # Refuse untrusted files before unlinking anything.
        self.path.unlink(missing_ok=True)


def diagnostic_report(*, status=None, keyring=None, probe=None, audit=None, egress=None, history=None, streaming=None):
    """Allowlist typed fields. Never export raw environment, logs, URLs or paths."""
    def booleans(source, allowed):
        return {key: value for key, value in (source or {}).items() if key in allowed and type(value) is bool}

    def checked_at(source):
        try:
            return datetime.fromisoformat(source["checked_at"]).isoformat(timespec="seconds")
        except (KeyError, ValueError, TypeError):
            return "not_observed"

    status, keyring, probe = status or {}, keyring or {}, probe or {}
    egress, audit = egress or {}, audit or {}
    streaming = streaming or {}
    return {"schema": 1, "version": __version__, "created_at": timestamp(),
            "account_safety": "not_assessed", "ip_redaction": "IPv4 /24; IPv6 /48; not anonymous",
            "isolation": {"state": "observed" if status else "not_tested", "kernel_ok": status.get("kernel_ok") is True,
                          "upstream_managed": status.get("upstream_managed") is True,
                          "upstream_test_only": status.get("upstream_test_only") is True,
                          "checks": booleans(status.get("checks"), {"configuration", "namespace_identity", "firewall", "no_external_route", "upstream_egress"})},
            "keyring": {"state": "observed" if keyring else "not_tested", "checked_at": checked_at(keyring),
                        "available_at_last_check": keyring.get("available") is True,
                        "actual_browser_backend": "not_observed", "encryption_at_rest": "not_observed"},
            "probe": {"state": "passed" if probe.get("passed") is True else "failed" if probe else "not_tested",
                      "checked_at": checked_at(probe),
                      "checks": booleans(probe.get("checks"), {"namespace_matches", "runtime_isolated", "runtime_isolated_after", "direct_ipv4_denied", "direct_ipv6_denied", "udp_dns_denied", "tcp_dns_denied", "dot_denied", "other_host_ports_denied", "system_dns_denied", "proxy_tls_verified"})},
            "environment_audit": {"scope": "current_process_environment_only",
                                  "state": "observed" if audit else "not_tested",
                                  "checked_at": checked_at(audit),
                                  "finding_ids": [item["id"] for item in audit.get("findings", [])
                                                  if isinstance(item, dict) and item.get("id") in FINDING_IDS]},
            "egress": {"target": EGRESS_TARGET,
                       "state": egress.get("status") if egress.get("status") in ("complete", "partial", "failed") else "not_tested",
                       "checked_at": checked_at(egress),
                       "observed_ips": [mask_ip(ip) for ip in egress.get("observed_ips", [])][:2],
                       "stable_during_sample": egress.get("stable_during_sample") if type(egress.get("stable_during_sample")) is bool else None,
                       "changed_since_previous": egress.get("changed_since_previous") if type(egress.get("changed_since_previous")) is bool else None,
                       "samples": [{"ok": sample.get("ok") is True,
                                    **{key: sample[key] for key in ("http_status", "tunnel_tls_ms", "response_headers_ms", "total_ms")
                                       if type(sample.get(key)) in (int, float) and 0 <= sample[key] < 1000000}}
                                   for sample in egress.get("samples", [])[:2]],
                       "anthropic_egress": "not_observed"},
            "streaming_transport": {"target": STREAM_TARGET, "scope": "generic_httpbin_https_stream_only",
                                    "state": streaming.get("status") if streaming.get("status") in ("passed", "inconclusive", "failed") else "not_tested",
                                    "checked_at": checked_at(streaming),
                                    "connection_reused": streaming.get("connection_reused") if type(streaming.get("connection_reused")) is bool else None,
                                    **{key: streaming[key] for key in ("control_http_status", "stream_http_status", "tunnel_tls_ms", "response_headers_ms", "stream_span_ms", "body_bytes", "meaningful_gap_count", "total_ms")
                                       if type(streaming.get(key)) in (int, float) and 0 <= streaming[key] < 1000000},
                                    "claude_streaming": "not_tested"},
            "egress_history": [{"checked_at": checked_at(entry), "ips": [mask_ip(ip) for ip in entry["ips"]]}
                               for entry in (history or [])[-30:]],
            "not_tested": ["browser_webrtc", "authoritative_dns_leak_test", "dns_packet_capture", "claude_streaming_connection"],
            "scope_note": "检测服务观测到的出口不证明 Anthropic 的实际出口；报告只反映已执行的检查，不计算封号概率。"}


def save_report(path, report):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        _check_file(stream.fileno())
        stream.truncate(0)
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
