# 代理与 DNS

v0.2 优先使用内置受控上游：字面公网 IPv4、TLS、远端域名 CONNECT、服务 UID 出站白名单。
参见 [受控上游与密钥链](UPSTREAM_AND_KEYRING.md)。下面的 sing-box 配置仅用于显式 --external-proxy 模式，不能当作 v0.2 已受内核约束的上游。

Claude Protect 的 relay 固定转发到 `127.0.0.1:20808`，不解析目标域名，不改写 HTTP，不解密 TLS。
在外部模式下需要自己管理该端口上的 HTTP CONNECT 代理；在受控模式下由本项目内置客户端监听，不要启动其他程序占用该端口。
不要将 SOCKS-only 端口直接填给安装器。

## 一个明确的 sing-box 路径

使用你自己已有、符合使用资格的上游 HTTP 代理。上游服务器填字面 IP，可避免 bootstrap DNS。
以下为不含凭据的配置结构示例；不是可直接运行的真实服务器配置。
实际配置在目标机器上通过 `sing-box check -c /配置路径/config.json` 验证。

```json
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": 20808 }
  ],
  "outbounds": [
    { "type": "http", "tag": "upstream", "server": "203.0.113.10", "server_port": 3128 }
  ],
  "route": { "final": "upstream" }
}
```

`203.0.113.10` 是文档地址，必须替换。只有一个代理 outbound，不配置 direct 或自动 fallback。
HTTP 上游接收目标域名的 CONNECT，目标解析由上游负责；上游地址使用字面 IP。
采用 SOCKS 上游时 sing-box 本地仍提供 HTTP/mixed 入站，远端 SOCKS 必须支持域名地址并进行远端解析。
HTTPS 上游应按供应商要求配置 TLS 和 server_name，保留证书校验，不能添加 `insecure: true`。

上游认证只应在本机权限为 0600 的配置中处理，不要放入命令行、工作区设置、截图、日志或源码包。
外部模式安装器不读取代理凭据；v0.2 受控模式通过 --upstream-auth 在本机提示输入供应商代理认证，并保存于 root:专用服务组的 0640 文件。
项目不读取 Claude 账号凭据，不提供代理购买或订阅代充功能。

若已有 Mihomo/其他代理，不必替换；应建立专用 HTTP 入口，核对完整路由和解析路径。
不要把“节点名固定”“TUN 开关开启”当作已验证。

## 与已有 TUN 模式共存

兼容模式可以保留 Mihomo TUN，relay 仍连接其本机 HTTP / 混合端口。
端口以代理软件实际设置为准，例如 `7897`；`20808` 只是默认值。
网段冲突检查会识别 TUN 接口上的大范围转发路由（例如 `0.0.0.0/1`），
仍拒绝真实的直连网段、本地地址及隔离网段内的具体路由冲突。
启动和状态检查还会确认到隔离端的回程走 `cp-host`；若被 TUN 策略接走则拒绝就绪，
需在代理软件中排除该私有 `/30`，本项目不会修改已有 TUN 规则。

若旧版因 TUN 路由误判而安装中断，且尚无隔离 namespace 或运行中的服务，
可在源码目录执行 `sudo python3 scripts/repair_tun.py --proxy-port 7897`（替换实际端口）。
该命令备份原文件、更新已安装的路由检查及外部代理端口，并启动本项目服务；
已有 namespace 或服务正在运行时拒绝覆盖。完成后刷新面板，再安装两个插件。

## 验证什么

在目标 Ubuntu 上同时观察：

- `cp-host` 上没有 DNS 请求；namespace 只能连接 relay 端口。
- 发送 Claude 请求时，主机物理网卡没有对应目标域名的本地 DNS 查询。
- 代理自身只连接预期上游；没有 DIRECT 分支、直连 DNS、DoH/DoT 旁路。
- 停止本地代理后，新请求失败，已有流连接中断，不出现新的直连。
- IPv6 与 IPv4 都满足相同的出口限制。

DoH 只是加密 DNS，必须核对它的连接是否经过预期链路。仅抓 53 端口无法发现所有 DoH/DoT。
使用仅单一上游的代理并限制其出口，比维护“所有 DNS 服务 IP 黑名单”更容易验证。

参考：[sing-box HTTP outbound](https://sing-box.sagernet.org/configuration/outbound/http/)、[Claude 官方网络配置](https://code.claude.com/docs/en/network-config)。
