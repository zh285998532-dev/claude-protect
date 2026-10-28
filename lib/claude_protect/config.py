"""Non-secret, root-owned deployment configuration."""
from dataclasses import dataclass, asdict
import ipaddress
import json
import os
from pathlib import Path
import stat

CONFIG = Path("/etc/claude-protect/config.json")
STATE_DIR = Path("/run/claude-protect")
STATE = STATE_DIR / "kernel.json"
HELPER = "/usr/local/libexec/claude-protect-helper"
NAMESPACE = "claude-protect"
HOST_LINK = "cp-host"
PEER_LINK = "cp-peer"
NS_LINK = "cp0"


@dataclass(frozen=True)
class Config:
    uid: int
    subnet: str = "10.254.253.0/30"
    relay_port: int = 19080
    upstream_port: int = 20808
    code: str = "/usr/bin/code"
    version: int = 2
    proxy_mode: str = "external"
    upstream_ip: str | None = None
    upstream_remote_port: int = 443
    upstream_tls_name: str | None = None
    upstream_tls: bool = True
    proxy_uid: int | None = None
    upstream_test_only: bool = False

    def __post_init__(self):
        if type(self.uid) is not int or self.uid <= 0:
            raise ValueError("uid must identify a non-root user")
        if self.version != 2:
            raise ValueError("unsupported configuration version")
        network = ipaddress.ip_network(self.subnet, strict=True)
        private_ranges = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                          ipaddress.ip_network("192.168.0.0/16"))
        if network.version != 4 or network.prefixlen != 30 or not any(network.subnet_of(block) for block in private_ranges):
            raise ValueError("subnet must be a private IPv4 /30 network")
        for port in (self.relay_port, self.upstream_port):
            if type(port) is not int or not 1024 <= port <= 65535:
                raise ValueError("ports must be integers between 1024 and 65535")
        if self.code != "/usr/bin/code":
            raise ValueError("supports the official VS Code .deb at /usr/bin/code only")
        if self.proxy_mode not in ("external", "managed"):
            raise ValueError("proxy mode must be external or managed")
        if type(self.upstream_remote_port) is not int or not 1 <= self.upstream_remote_port <= 65535:
            raise ValueError("invalid upstream port")
        if type(self.upstream_tls) is not bool:
            raise ValueError("upstream_tls must be boolean")
        if type(self.upstream_test_only) is not bool:
            raise ValueError("upstream_test_only must be boolean")
        if self.proxy_mode == "managed":
            if not self.upstream_ip or ipaddress.ip_address(self.upstream_ip).version != 4:
                raise ValueError("managed upstream requires a literal IPv4 address; hostname/bootstrap DNS is not used")
            if not self.upstream_test_only and (not ipaddress.ip_address(self.upstream_ip).is_global or not self.upstream_tls):
                raise ValueError("production upstream must be a public IPv4 address with TLS; private/plaintext endpoints are test-only")
            if type(self.proxy_uid) is not int or self.proxy_uid <= 0 or self.proxy_uid == self.uid:
                raise ValueError("managed proxy requires a separate non-root service UID")
            if self.upstream_tls_name is not None:
                import re
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", self.upstream_tls_name):
                    raise ValueError("invalid upstream TLS name")
        elif any(value is not None for value in (self.upstream_ip, self.upstream_tls_name, self.proxy_uid)):
            raise ValueError("external mode must not claim managed upstream settings")

    @property
    def gateway(self):
        return str(ipaddress.ip_network(self.subnet).network_address + 1)

    @property
    def client(self):
        return str(ipaddress.ip_network(self.subnet).network_address + 2)

    @property
    def proxy_url(self):
        return f"http://{self.gateway}:{self.relay_port}"

    def to_dict(self):
        return asdict(self)


def trusted_file(path):
    """Check the complete path, not just the final symlink target."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("trusted path must be absolute")
    for part in [path, *path.parents]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"symlink not allowed in protected configuration path: {part}")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f"path must be root-owned and not group/world writable: {part}")
    if not path.is_file():
        raise ValueError(f"not a regular file: {path}")


def load_config(path=CONFIG):
    trusted_file(path)
    return Config(**json.loads(Path(path).read_text()))


def atomic_json(path, data, mode=0o644):
    path = Path(path)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(data, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
