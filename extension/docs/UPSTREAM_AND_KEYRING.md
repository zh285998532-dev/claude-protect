# v0.2 受控上游与 Secret Service

本轮只实现第二、第三项优化。用户将稍后在 Ubuntu 验收；未创建虚拟机或连接用户测试机。

## 受控上游

`--upstream-ip` 选择受控模式。创建锁定的系统账号 `claude-protect-proxy`，运行内置 HTTP CONNECT 客户端。
程序仅连接字面公网 IPv4，使用 TLS 并按 `--upstream-tls-name` 或 IP 验证远端证书，不启用 TLS 解密或忽略校验。
客户端重建最小 CONNECT 请求，将目标域名留给上游解析；客户端提供的代理认证头等信息不被转发。
供应商代理认证来自 `/etc/claude-protect/upstream-credentials.json`，权限 0640，root:专用服务组；无凭据时也使用该权限。
这个文件不含 Claude 账号信息，安装密码只在本机终端输入，不接受密码命令行参数。

主机新增 `inet claude_protect_upstream`，只匹配上述服务 UID：

1. 允许 127.0.0.1 上本地代理端口的已建立连接回复。
2. 允许到唯一指定上游 IPv4:TCP 端口的连接。
3. 丢弃该 UID 的其余出站，包括其他 DNS、IPv6 和 DoH 地址。

其他 UID 默认不受本表影响，已有防火墙的拒绝规则也不会被本表绕过。
上游过滤规则在服务启动前创建，摘要进入受保护状态。服务不可达时返回明确网关失败，不改成直连目标。
上游规则缺失/被修改时，状态检查失败并拒绝新启动；不自动修改规则来让请求继续。
管理员拥有 root 时仍然可以修改/移除限制，这不是对抗宿主 root 的安全边界。

目前支持 HTTPS CONNECT 代理（HTTP/1.x），目标端口固定 443。HTTPS 目标的 TLS 内容原样隧道转发。
不支持 SOCKS 上游、非 443 目标、HTTP/2-only 代理、域名形式的连接端点或代理池自动轮换。
若现有服务不支持此协议，应明确使用外部模式，不能把外部模式显示为完整上游控制。

`--external-proxy` 保留 v0.1 本地代理模式；只证明应用隔离，不能证明代理自身 DNS/出口受控。
`--allow-test-upstream --upstream-no-tls` 仅用于可恢复测试机的本地 fixture；禁止搭配认证，界面会标为测试配置。
生产安装不接受私网/loopback 上游，也不接受明文上游，因此不会把本机不受控的代理悄悄包装成“受控远端”。

## 密钥链通道

Ubuntu 会话总线原路径仍在私有 mount 中屏蔽；应用只能看见：

```text
unix:path=/run/user/UID/claude-protect-keyring/bus
```

这是 `xdg-dbus-proxy --filter`，由当前桌面用户的 systemd 用户服务启动。
只允许 `org.freedesktop.secrets` 上列出的 Secret.Service、Collection、Item、Session、Prompt 方法，受对象路径约束；另允许必要的 Properties/Introspect 和 Secret 信号。
没有对整个会话总线的 `--talk` 放行，不开放 resolver、systemd 管理、OpenURI/桌面门户或系统 D-Bus。
这是一项服务/方法级过滤，不是单个 secret 的应用级 ACL。受保护代码仍是本人用户权限下的程序，不能把它当作恶意代码文件/凭据沙箱。

启动 Code/Chrome 前：

1. 检查 `libsecret-1.so.0` 可加载。
2. 检查过滤 socket 的类型、用户和私有目录权限。
3. 通过过滤通道读取默认 collection 的别名和 `Locked` 属性。
4. 默认 collection 不存在、服务失联或锁定时拒绝启动。由本人在正常桌面的密码管理器解锁；项目不索取 keyring 口令。
5. Code 和 Chrome 明确带 `--password-store=gnome-libsecret`，不会由本项目添加 basic/no-sandbox 兜底。

即使绕过 CLI 直接调用 root helper，最终的非特权 session guard 也会重做上述检查。
v0.2 的 Chrome 使用新 `browser-v2` profile，保留旧版 `browser` 目录但不自动导入其中的 Cookie/密码。

## 预检结果的准确含义

```bash
claude-protect keyring-status --json
python3 scripts/keyring_acceptance.py
```

前者只检查 Secret Service 可用且解锁。后者还检查危险服务不可见/调用被拒绝。
两者不调用 GetSecret/GetSecrets，不导出密码、Cookie、OAuth URL、收藏或网站列表。

结果明确包含 `actual_browser_backend: not_observed` 和 `collection_encryption_at_rest: not_observed`。
原因是：请求 gnome-libsecret 和服务预检成功，并不能证明某个 Chrome 版本最终选择了该后端，也不能证明用户给密钥链设置了非空加密口令。
Chromium 官方仍说明不可用时可能回退 basic，因此不能用启动参数替代实际存储验收。
如果启动后密钥链异常，关闭受保护应用，恢复服务后再启动；当前版本没有宣称能在任意 Chrome 内部故障时强制阻止所有后端回退。

在 Ubuntu 的第一次登录前，先确认宿主默认密钥链有真实口令、正常解锁；在不含真实账号的测试 profile 下核对当前 Chrome/Code 的实际存储后端。
`chrome://version` 只能核对请求参数，不是实际后端证明。不要通过把密码/Cookie 数据库发给助手来验收。
浏览器升级、密钥链实现切换或 D-Bus 配置变化后重新验收。

## 本轮可测试与待测试

本地 socket/单元测试覆盖：固定端点、保持域名 CONNECT、上游错误/拒绝、客户端头剥离、认证注入、生产配置拒绝、UID 规则范围、过滤规则、密钥链锁定/缺失阻断和自然 locale 传递。
用户后续可运行 `scripts/linux_acceptance.py --managed`，核对真正的 UID nftables 限制、DNS 丢弃计数、规则篡改拒绝和卸载恢复。
Ubuntu 桌面实际 Chrome、Secret Service、授权、磁盘存储后端与重启均尚未验收。

来源：[xdg-dbus-proxy](https://github.com/flatpak/xdg-dbus-proxy)、[Secret Service](https://specifications.freedesktop.org/secret-service/latest/)、[Chromium Linux Password Storage](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/password_storage.md)。
