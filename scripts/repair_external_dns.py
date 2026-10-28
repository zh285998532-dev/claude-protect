#!/usr/bin/env python3
"""One-off, explicit admin repair of this desktop user's Clash DNS configuration."""
import copy
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from claude_protect.config import load_config, atomic_json
from claude_protect.external_audit import dns_query, read_runtime_dns
from claude_protect.diagnostics import timestamp


def repair():
    config = load_config()
    if os.geteuid() != 0 or os.environ.get('SUDO_UID') != str(config.uid) or config.proxy_mode != 'external':
        raise ValueError('Run with sudo as the configured desktop user in external proxy mode')
    runtime = Path(f'/var/lib/clash-verge-service/users/{config.uid}/runtime/config.yaml')
    for path in [runtime, *runtime.parents]:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted runtime configuration path')
    original = runtime.read_bytes()
    settings = yaml.safe_load(original)
    updated = copy.deepcopy(settings)
    current_dns = updated.setdefault('dns', {})
    resolvers = current_dns.get('nameserver')
    if not isinstance(resolvers, list) or not resolvers:
        raise ValueError('Missing existing node bootstrap resolvers')
    current_dns['respect-rules'] = True
    current_dns['proxy-server-nameserver'] = copy.deepcopy(resolvers)
    policies = current_dns.setdefault('nameserver-policy', {})
    for domain in ('+.claude.ai', '+.claude.com', '+.anthropic.com'):
        policies[domain] = 'https://1.1.1.1/dns-query#GLOBAL'
    assert {k:v for k,v in updated.items() if k != 'dns'} == {k:v for k,v in settings.items() if k != 'dns'}
    replacement = yaml.safe_dump(updated, allow_unicode=True, sort_keys=False).encode()
    backup = Path('/etc/claude-protect/clash-dns-before-repair.yaml')
    if not backup.exists():
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(original)
    controller = Path(f'/run/clash-verge-service/users/{config.uid}/verge-mihomo.sock')
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(12)
            self.sock.connect(str(controller))
    def request(method, endpoint, body=None):
        client = Connection('localhost', timeout=12)
        try:
            client.request(method, endpoint, body=json.dumps(body).encode() if body is not None else None,
                           headers={'Content-Type':'application/json'})
            response = client.getresponse()
            raw = response.read(2 * 1024 * 1024)
            if not 200 <= response.status < 300:
                raise RuntimeError('Core rejected configuration; HTTP ' + str(response.status))
            return json.loads(raw) if raw else {}
        finally:
            client.close()
    before = request('GET', '/configs')
    proxies = request('GET', '/proxies')['proxies']
    selected = proxies.get('GLOBAL', {}).get('now')
    if before.get('mixed-port') != config.upstream_port or before.get('mode') != 'global' or not selected:
        raise ValueError('Expected the existing matching global-mode proxy')
    def replace(raw):
        fd, name = tempfile.mkstemp(prefix='.dns-repair-', dir=runtime.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(name, stat.S_IMODE(runtime.stat().st_mode))
            os.replace(name, runtime)
        finally:
            Path(name).unlink(missing_ok=True)
    def apply(raw):
        replace(raw)
        request('PUT', '/configs?force=true', {'path': str(runtime)})
        now = request('GET', '/proxies')['proxies'].get('GLOBAL', {}).get('now')
        if now != selected:
            request('PUT', '/proxies/GLOBAL', {'name':selected})
    changed = False
    try:
        if runtime.read_bytes() != original:
            raise RuntimeError('Configuration changed before repair')
        changed = True
        apply(replacement)
        outcome = dns_query(controller)
        if outcome.get('ok') is not True:
            raise RuntimeError('Claude DNS positive control did not pass')
        after = request('GET', '/configs')
        if any(after.get(key) != before.get(key) for key in ('mode', 'mixed-port', 'ipv6', 'tun')):
            raise RuntimeError('Non-DNS runtime settings changed')
        read_runtime_dns()
        print('修复成功：Claude DNS 查询已通过，原节点、代理模式和 TUN 配置已核对。')
        print('已保留原配置备份。请以面板重新检测得到的本次结果为准。')
    except BaseException:
        if changed:
            apply(original)
            print('验证未通过，Clash 运行配置已回滚。')
        raise


if __name__ == '__main__':
    def expired(signum, frame):
        raise TimeoutError('Repair deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(75)
    successful = False
    try:
        repair()
        successful = True
    except Exception as error:
        print('修复未完成：' + type(error).__name__ + '。未输出原始配置或代理凭据。', file=sys.stderr)
        raise SystemExit(1)
    finally:
        signal.alarm(0)
        if os.geteuid() == 0:
            atomic_json(Path('/run/claude-protect/dns-repair-result.json'),
                        {'status': 'passed' if successful else 'failed', 'checked_at': timestamp()})
