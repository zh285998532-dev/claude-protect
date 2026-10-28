"""Small privileged control plane. No forwarding, NAT, or host firewall edits."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from .config import (HOST_LINK, NAMESPACE, NS_LINK, PEER_LINK, STATE, STATE_DIR,
                     atomic_json, trusted_file)

TOOLS = {name: f"/usr/sbin/{name}" for name in ("ip", "nft", "sysctl")}
# Ubuntu's merged-/usr installations provide ip and mount via these paths.
TOOLS.update({"mount": "/usr/bin/mount", "umount": "/usr/bin/umount"})
ROOT_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


def run(args, *, data=None, check=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True,
                            env=ROOT_ENV, timeout=20, check=False, cwd="/")
    if check and result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed: {result.stderr.strip()}")
    return result


def ns_command(*args):
    return [TOOLS["ip"], "netns", "exec", NAMESPACE, *args]


def nft_policy(config):
    return f"""table inet claude_protect {{
  chain output {{
    type filter hook output priority 0; policy drop;
    meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} counter drop
    oifname \"lo\" counter accept
    ip daddr {config.gateway} tcp dport {config.relay_port} ct state {{ new, established }} counter accept
  }}
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname \"lo\" counter accept
    ip saddr {config.gateway} tcp sport {config.relay_port} ct state established counter accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
}}
"""


def canonical_rules(document):
    """Ignore volatile packet counts/handles; retain every effective rule."""
    def clean(value):
        if isinstance(value, list):
            return [clean(item) for item in value
                    if not (isinstance(item, dict) and "metainfo" in item)]
        if isinstance(value, dict):
            return {key: ({} if key == "counter" else clean(item))
                    for key, item in value.items() if key not in ("handle", "index")}
        return value
    return json.dumps(clean(document), sort_keys=True, separators=(",", ":"))


def rules_digest(document):
    return hashlib.sha256(canonical_rules(document).encode()).hexdigest()


def observe():
    nft = json.loads(run(ns_command(TOOLS["nft"], "-j", "list", "ruleset")).stdout)
    routes = json.loads(run([TOOLS["ip"], "-n", NAMESPACE, "-j", "-4", "route", "show", "table", "main"]).stdout)
    routes6 = json.loads(run([TOOLS["ip"], "-n", NAMESPACE, "-j", "-6", "route", "show", "table", "main"]).stdout)
    addresses = json.loads(run([TOOLS["ip"], "-n", NAMESPACE, "-j", "address", "show", "dev", NS_LINK]).stdout)
    return {
        "namespace_inode": os.stat(f"/run/netns/{NAMESPACE}").st_ino,
        "rules_sha256": rules_digest(nft),
        "routes": routes,
        "routes6": routes6,
        "addresses": [{"local": item["local"], "prefixlen": item["prefixlen"], "family": item["family"]}
                      for link in addresses for item in link.get("addr_info", [])],
    }


def topology_ok(config, observed):
    routes = observed["routes"]
    return (len(routes) == 1
            and routes[0].get("dst") == config.subnet
            and routes[0].get("dev") == NS_LINK
            and routes[0].get("scope") == "link"
            and not routes[0].get("gateway")
            and observed["routes6"] == []
            and observed["addresses"] == [{"local": config.client, "prefixlen": 30, "family": "inet"}])


def status(config):
    trusted_file(STATE)
    saved = json.loads(STATE.read_text())
    current = observe()
    checks = {
        "configuration": saved.get("config") == config.to_dict(),
        "namespace_identity": current["namespace_inode"] == saved.get("namespace_inode"),
        "firewall": current["rules_sha256"] == saved.get("rules_sha256"),
        "no_external_route": topology_ok(config, current),
        "host_return_route": host_route_ok(config),
    }
    if config.proxy_mode == "managed":
        from .upstream_policy import observe as upstream_observe
        expected = saved.get("upstream_rules_sha256")
        checks["upstream_egress"] = bool(expected and upstream_observe() == expected)
    return {"schema": 1, "kernel_ok": all(checks.values()), "checks": checks,
            "namespace_inode": current["namespace_inode"], "proxy_url": config.proxy_url,
            "uid": config.uid, "upstream_managed": config.proxy_mode == "managed",
            "upstream_test_only": config.upstream_test_only}


def ensure_no_collision(config):
    import ipaddress
    network = ipaddress.ip_network(config.subnet)
    routes = json.loads(run([TOOLS["ip"], "-j", "-4", "route", "show", "table", "all"]).stdout)
    links = json.loads(run([TOOLS["ip"], "-d", "-j", "link", "show"]).stdout)
    tun_links = {link["ifname"] for link in links
                 if link.get("linkinfo", {}).get("info_kind") == "tun"}
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        try:
            other = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.overlaps(other):
            # TUN catch-all forwarding routes do not allocate their destination
            # ranges. The new connected /30 must still win the actual lookup.
            if (route.get("dev") in tun_links and other != network and network.subnet_of(other)
                    and route.get("scope") != "link" and route.get("type", "unicast") == "unicast"):
                continue
            raise RuntimeError(f"subnet conflicts with an existing host route: {destination}; choose another private /30")


def host_route_ok(config):
    # status() also runs from the inner launcher, already inside the application
    # network namespace. Query the host explicitly in both contexts.
    routes = json.loads(run(["/usr/bin/nsenter", "--net=/proc/1/ns/net", "--",
                             TOOLS["ip"], "-j", "-4", "route", "get", config.client]).stdout)
    return (len(routes) == 1 and routes[0].get("dev") == HOST_LINK
            and not routes[0].get("gateway")
            and routes[0].get("prefsrc") == config.gateway)


def setup(config):
    namespace = Path(f"/run/netns/{NAMESPACE}")
    if namespace.exists():
        if not status(config)["kernel_ok"]:
            raise RuntimeError("existing namespace differs from installed policy; refusing to overwrite it")
        return
    if STATE.exists():
        raise RuntimeError("stale state exists; inspect and run teardown before setup")
    if run([TOOLS["ip"], "link", "show", HOST_LINK], check=False).returncode == 0:
        raise RuntimeError("cp-host already exists; refusing to change an unowned interface")
    ensure_no_collision(config)
    STATE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    created_namespace = created_link = False
    upstream_digest = None
    try:
        run([TOOLS["ip"], "netns", "add", NAMESPACE])
        created_namespace = True
        run([TOOLS["ip"], "link", "add", HOST_LINK, "type", "veth", "peer", "name", PEER_LINK])
        created_link = True
        run([TOOLS["ip"], "link", "set", PEER_LINK, "netns", NAMESPACE])
        run([TOOLS["ip"], "-n", NAMESPACE, "link", "set", PEER_LINK, "name", NS_LINK])
        # Only this new network namespace is changed. Host IPv6 is untouched.
        run(ns_command(TOOLS["sysctl"], "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1",
                       "net.ipv6.conf.default.disable_ipv6=1"))
        run([TOOLS["ip"], "address", "add", f"{config.gateway}/30", "dev", HOST_LINK])
        run([TOOLS["ip"], "-n", NAMESPACE, "address", "add", f"{config.client}/30", "dev", NS_LINK])
        # Install the deny policy BEFORE bringing either veth endpoint up.
        run(ns_command(TOOLS["nft"], "-f", "-"), data=nft_policy(config))
        if config.proxy_mode == "managed":
            from .upstream_policy import setup as upstream_setup
            upstream_digest = upstream_setup(config)
            if not upstream_digest:
                raise RuntimeError("upstream firewall could not be verified")
        for command in ([TOOLS["ip"], "link", "set", HOST_LINK, "up"],
                        [TOOLS["ip"], "-n", NAMESPACE, "link", "set", NS_LINK, "up"],
                        [TOOLS["ip"], "-n", NAMESPACE, "link", "set", "lo", "up"]):
            run(command)
        current = observe()
        if not topology_ok(config, current):
            raise RuntimeError("new namespace failed route/address verification")
        if not host_route_ok(config):
            raise RuntimeError("host return route is intercepted; exclude the private /30 from TUN routing")
        atomic_json(STATE, {**current, "config": config.to_dict(), "upstream_rules_sha256": upstream_digest})
    except BaseException:
        if upstream_digest:
            from .upstream_policy import remove as upstream_remove
            upstream_remove(upstream_digest)
        if created_link:
            run([TOOLS["ip"], "link", "delete", HOST_LINK], check=False)
        if created_namespace:
            run([TOOLS["ip"], "netns", "delete", NAMESPACE], check=False)
        STATE.unlink(missing_ok=True)
        raise


def teardown(config):
    namespace = Path(f"/run/netns/{NAMESPACE}")
    if namespace.exists():
        trusted_file(STATE)
        saved = json.loads(STATE.read_text())
        if saved.get("namespace_inode") != namespace.stat().st_ino:
            raise RuntimeError("namespace identity changed; refusing to remove it")
        pids = run([TOOLS["ip"], "netns", "pids", NAMESPACE]).stdout.strip()
        if pids:
            raise RuntimeError("protected processes are still running; close the protected VS Code window first")
        if config.proxy_mode == "managed":
            from .upstream_policy import remove as upstream_remove
            upstream_remove(saved.get("upstream_rules_sha256"))
        run([TOOLS["ip"], "netns", "delete", NAMESPACE])
        run([TOOLS["ip"], "link", "delete", HOST_LINK], check=False)
    elif STATE.exists():
        # Never delete an interface based solely on its name after losing the namespace.
        if run([TOOLS["ip"], "link", "show", HOST_LINK], check=False).returncode == 0:
            raise RuntimeError("namespace missing but cp-host exists; manual inspection required")
        if config.proxy_mode == "managed":
            trusted_file(STATE)
            saved = json.loads(STATE.read_text())
            if saved.get("config") != config.to_dict():
                raise RuntimeError("saved upstream ownership is unverified; refusing to remove host policy")
            from .upstream_policy import remove as upstream_remove
            upstream_remove(saved.get("upstream_rules_sha256"))
    STATE.unlink(missing_ok=True)
