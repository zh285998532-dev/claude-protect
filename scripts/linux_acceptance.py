#!/usr/bin/env python3
"""Destructive only to this project's new test installation. Disposable Ubuntu only."""
import argparse
import json
import os
from pathlib import Path
import pwd
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from claude_protect.config import CONFIG, Config, load_config
from claude_protect.kernel import canonical_rules, nft_policy
from claude_protect.upstream_policy import TABLE, policy as upstream_policy


def run(args, check=True, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=90, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"command failed: {args[0]}\n{result.stderr}")
    return result


def ready(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=15) or process.stdout.readline().strip() != "ready":
            raise RuntimeError("fixture/tunnel did not become ready")


def main():
    parser = argparse.ArgumentParser(description="Run only on a disposable Ubuntu VM/CI runner")
    parser.add_argument("--user", required=True)
    parser.add_argument("--managed", action="store_true", help="test service-UID egress policy and the built-in upstream client")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Ubuntu root required")
    user = pwd.getpwnam(args.user)
    if user.pw_uid == 0 or CONFIG.exists():
        parser.error("a non-root user and a fresh machine without Claude Protect are required")
    if not shutil.which("tcpdump"):
        parser.error("install tcpdump first")
    port = 21808
    config = Config(uid=user.pw_uid, upstream_port=port)
    host_before = canonical_rules(json.loads(run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout))
    processes = []
    installed = False
    reports = {}
    report_path = ROOT / ("dist/linux-acceptance-managed.json" if args.managed else "dist/linux-acceptance-external.json")
    report_path.parent.mkdir(exist_ok=True)
    as_user = ["/usr/sbin/runuser", "-u", args.user, "--", "/usr/local/bin/claude-protect"]
    try:
        fixture_port = 21809 if args.managed else port
        fixture = subprocess.Popen(["/usr/bin/python3", str(ROOT / "tests/connect_fixture.py"), str(fixture_port)],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        processes.append(fixture)
        ready(fixture)
        # Mark before invoking installer so a partial install is also cleaned up.
        installed = True
        install = ["/usr/bin/python3", str(ROOT / "scripts/install.py"), "--user", args.user, "--proxy-port", str(port)]
        if args.managed:
            install += ["--upstream-ip", "127.0.0.1", "--upstream-port", str(fixture_port),
                        "--allow-test-upstream", "--upstream-no-tls"]
        else:
            install += ["--external-proxy"]
        run(install)
        config = load_config()
        for _ in range(30):
            result = run(as_user + ["status", "--json"], check=False)
            if result.returncode == 0:
                break
            time.sleep(0.2)
        normal = json.loads(result.stdout)
        assert normal["kernel_ok"] and not normal["session_isolated"], normal
        reports["ordinary_window_not_protected"] = True
        assert normal["upstream_managed"] == args.managed
        if args.managed:
            # Test the UID firewall using a different program under the service
            # identity, so the result is not merely the proxy's own code behavior.
            service_probe = """import socket,json
def connects(host,port):
 s=socket.socket(); s.settimeout(0.6)
 try: s.connect((host,port)); return True
 except OSError: return False
 finally: s.close()
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); dns.settimeout(0.6)
try:
 dns.sendto(bytes.fromhex('435001000001000000000000076578616d706c6503636f6d0000010001'),('1.1.1.1',53))
 dns.recvfrom(512); denied=False
except OSError: denied=True
finally: dns.close()
print(json.dumps({'allowed_endpoint':connects('127.0.0.1',21809),'other_tcp_denied':not connects('1.1.1.1',443),'dns_denied':denied}))
"""
            uid_probe = run(["/usr/bin/setpriv", "--reuid", str(config.proxy_uid), "--regid", str(pwd.getpwuid(config.proxy_uid).pw_gid),
                             "--clear-groups", "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3", "-c", service_probe])
            observed = json.loads(uid_probe.stdout)
            assert all(observed.values()), observed
            rules = json.loads(run(["/usr/sbin/nft", "-j", "list", "table", "inet", TABLE]).stdout)
            drops = [expr["counter"].get("packets", 0) for entry in rules["nftables"] if "rule" in entry
                     and any("drop" in expr for expr in entry["rule"].get("expr", []))
                     for expr in entry["rule"]["expr"] if "counter" in expr]
            assert sum(drops) > 0, "service UID drop counter did not move"
            reports["managed_uid_egress"] = observed
        with tempfile.TemporaryDirectory(prefix="cp-acceptance-") as folder:
            pcap = Path(folder) / "dns.pcap"
            capture = subprocess.Popen([shutil.which("tcpdump"), "-ni", "cp-host", "-U", "-w", str(pcap),
                                        "port 53 or port 853"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(capture)
            time.sleep(0.5)
            if capture.poll() is not None:
                raise RuntimeError("DNS capture did not start; cannot claim a leak test passed")
            positive = json.loads(run(as_user + ["probe"]).stdout)
            assert positive["passed"], positive
            reports["positive_and_negative_route_checks"] = positive
            # Keep one existing CONNECT tunnel open, then stop the actual relay service.
            snippet = f"""import socket,sys
s=socket.create_connection(({config.gateway!r},{config.relay_port}),timeout=15)
s.sendall(b'CONNECT example.com:443 HTTP/1.1\\r\\nHost: example.com:443\\r\\n\\r\\n')
data=b''
while not data.endswith(b'\\r\\n\\r\\n'): data += s.recv(1)
assert b'200' in data
print('ready',flush=True)
assert s.recv(1)==b''
"""
            tunnel = subprocess.Popen(["/usr/sbin/ip", "netns", "exec", "claude-protect", "/usr/bin/setpriv",
                                       "--reuid", str(user.pw_uid), "--regid", str(user.pw_gid), "--init-groups",
                                       "--bounding-set=-all", "--no-new-privs", "/usr/bin/python3", "-c", snippet],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(tunnel)
            ready(tunnel)
            assert tunnel.poll() is None, "tunnel closed before the outage test"
            run(["/usr/bin/systemctl", "stop", "claude-protect-relay.service"])
            assert tunnel.wait(timeout=10) == 0, "established tunnel survived relay shutdown"
            reports["established_tunnel_closed"] = True
            offline = run(as_user + ["probe"], check=False)
            negative = json.loads(offline.stdout)
            assert offline.returncode != 0 and not negative["checks"]["proxy_tls_verified"], negative
            assert all(value for key, value in negative["checks"].items() if key != "proxy_tls_verified"), negative
            reports["relay_outage_fail_closed"] = negative
            run(["/usr/bin/systemctl", "start", "claude-protect-relay.service"])
            # Alter the real namespace firewall; the status/launcher must reject it.
            run(["/usr/sbin/ip", "netns", "exec", "claude-protect", "/usr/sbin/nft", "delete", "table", "inet", "claude_protect"])
            altered = run(as_user + ["status", "--json"], check=False)
            assert altered.returncode != 0 and not json.loads(altered.stdout)["kernel_ok"]
            refused = run(as_user + ["launch", user.pw_dir], check=False)
            assert refused.returncode != 0, "launcher accepted altered rules"
            reports["tampered_firewall_refuses_launch"] = True
            run(["/usr/sbin/ip", "netns", "exec", "claude-protect", "/usr/sbin/nft", "-f", "-"], input=nft_policy(config))
            assert json.loads(run(as_user + ["status", "--json"]).stdout)["kernel_ok"]
            if args.managed:
                run(["/usr/bin/systemctl", "stop", "claude-protect-upstream.service"])
                run(["/usr/sbin/nft", "delete", "table", "inet", TABLE])
                damaged = run(as_user + ["status", "--json"], check=False)
                assert damaged.returncode != 0 and not json.loads(damaged.stdout)["checks"]["upstream_egress"]
                reports["managed_filter_tamper_detected"] = True
                run(["/usr/sbin/nft", "-f", "-"], input=upstream_policy(config))
                run(["/usr/bin/systemctl", "start", "claude-protect-upstream.service"])
                assert json.loads(run(as_user + ["status", "--json"]).stdout)["kernel_ok"]
            capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)
            packets = run([shutil.which("tcpdump"), "-nn", "-r", str(pcap)]).stdout.strip()
            assert not packets, "DNS packets escaped onto cp-host"
            reports["veth_dns_capture_empty"] = True
        host_document = json.loads(run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout)
        if args.managed:
            host_document["nftables"] = [entry for entry in host_document["nftables"]
                if not any(isinstance(value, dict) and (value.get("table") == TABLE or
                    (key == "table" and value.get("name") == TABLE)) for key, value in entry.items())]
        host_after = canonical_rules(host_document)
        assert host_before == host_after, "host firewall changed"
        reports["host_firewall_unchanged"] = True
        reports["passed"] = True
    except BaseException as error:
        reports["passed"] = False
        reports["error"] = str(error)
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if installed and CONFIG.exists():
            cleanup = run(["/usr/bin/python3", str(ROOT / "scripts/uninstall.py")], check=False)
            reports["cleanup_succeeded"] = cleanup.returncode == 0
            if cleanup.returncode:
                reports["passed"] = False
                reports["cleanup_error"] = cleanup.stderr
            else:
                restored = canonical_rules(json.loads(run(["/usr/sbin/nft", "-j", "list", "ruleset"]).stdout))
                reports["host_firewall_restored"] = restored == host_before
                if restored != host_before:
                    reports["passed"] = False
        report_path.write_text(json.dumps(reports, indent=2) + "\n")
    if not reports.get("passed"):
        raise RuntimeError("acceptance or cleanup failed; see dist/linux-acceptance-*.json")
    print(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
