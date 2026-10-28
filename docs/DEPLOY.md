# Ubuntu 部署、登录与验收

## 部署前

- 本版本面向 Ubuntu 桌面本地 VS Code，使用 Microsoft 官方 .deb；`/usr/bin/code` 必须由 root 管理。
- 新建的专用 VS Code 窗口有独立扩展目录。需要在该目录安装官方 `anthropic.claude-code` 和本项目 VSIX。
- 检查 `10.254.253.0/30` 不与现有 VPN/LAN/容器网段重叠；有冲突时安装命令指定另一个私有 `/30`。
- 优先准备支持 TLS 和证书校验的远端 HTTP/1.x CONNECT 代理，用公网字面 IPv4 配置受控模式；已有本地代理仅通过明确的外部模式使用。
- 安装 xdg-dbus-proxy、libglib2.0-bin、libsecret-1-0 和 GNOME/Secret Service 密钥链。登录桌面并解锁默认 collection；缺少库、过滤通道或未解锁时拒绝启动 GUI。
- 不自动降低 Ubuntu AppArmor/user namespace 或 Electron sandbox 安全设置。若桌面启动失败，应检查发行版与官方 Code sandbox 配置，不能添加 `--no-sandbox`。

## 首次登录

本项目不读取、导入、修改或自动填写 Claude 凭据。官方插件仍可使用本人已有的官方认证状态。
独立 Code profile 不代表官方 `~/.claude` 账户配置完全隔离。

首次授权应使用同一 namespace 内的浏览器。安装官方 Google Chrome .deb，运行 `claude-protect browser https://claude.ai/`。
受保护环境设置专用 `BROWSER` 和独立 XDG MIME 配置。HTTP(S) URL 由专用 Chrome profile 打开，`vscode://anthropic.claude-code/...` 交给受保护 Code profile；不会改主机 MIME 默认值。
同一 namespace 的浏览器可访问该环境的 loopback OAuth 回调。URL handler 不回显带有授权码的 URL，不处理其他扩展的 vscode:// URL。
桌面组件若忽略 BROWSER/XDG 而打开主机浏览器，应停止该登录，先检查实际进程 namespace，不临时放宽出口规则。
如果官方流程提供手动授权码，也可以在受保护终端使用官方 CLI 的 `/login`，由本人完成浏览器验证并手动返回官方授权码。
不把授权码粘贴给本插件或任何第三方。当前官方版本若不兼容这些路径，应记录问题并停止首次登录。
已有官方登录状态能否复用，以及具体官方插件版本的授权路径，必须在 Ubuntu 实机验收，不能仅凭单测宣布完成。

## 日常使用 Claude 网页版

通过应用菜单的“Claude Protect — 受保护浏览器”或 `claude-protect browser https://claude.ai/` 打开。
v0.2 专用 Chrome profile 位于 `~/.local/share/claude-protect/browser-v2/`，保持登录状态，不使用隐身模式，不复制普通浏览器或 v0.1 profile 的凭据。
即使当时没有打开受保护 VS Code，浏览器入口也会进入同一内核隔离环境。
安装器没有改变主机默认浏览器；从普通快捷方式打开的浏览器属于隔离外流程。

实机验收时，在普通终端检查实际 Chrome 主进程的 `/proc/<PID>/ns/net`，应与 `/run/netns/claude-protect` 一致。
然后验证网页版登录、本人使用的 Google/邮箱登录方式、网页流式回复和系统重启后的会话恢复。
停止 relay 后，应分别检查网页版的新请求和已有连接均失败，而不是只测 VS Code。
不能把 VS Code 状态栏显示为已隔离，当作任意外部浏览器也已受保护的证据。

## 基础检查

普通窗口运行 `claude-protect status` 应显示 kernel_ok 可为 true，但 session_isolated 为 false。
受保护窗口运行相同命令，kernel_ok、session_isolated、所有 runtime_checks 应为 true。

```bash
systemctl status claude-protect-network claude-protect-relay claude-protect-status
# 受控模式还有 claude-protect-upstream.service
claude-protect status --json
claude-protect probe
claude-protect keyring-status --json
```

probe 在受保护环境内运行，不使用账号；连接 `example.com` 的 TLS 校验必须成功，全部拒绝项必须通过。
拒绝项即使全部通过，但正向控制失败，也不能认定网络配置正常。

## DNS 与断线验收

在第二个普通终端抓包：

```bash
sudo tcpdump -ni cp-host 'port 53 or port 853'
```

在受保护窗口触发真实官方 Claude 请求并执行解析测试。记录接口、时间、插件版本、抓包结果。
同时检查物理出口和代理日志，排除主机代理自己进行的本地解析；不要保存提示词、Token 或认证头。
浏览器 DNS 检测页不能代替这一步。

确认当前没有重要任务后，在普通终端停止 relay：

```bash
sudo systemctl stop claude-protect-relay
```

在受保护窗口确认新请求失败，已有流式连接断开，主机无对应直连。
恢复：

```bash
sudo systemctl start claude-protect-relay
```

检查插件更新、窗口重启和系统重启后规则仍生效。状态后台检查只能发现异常，不能撤回已经发出的数据。

## 自动 Linux 验收

`scripts/linux_acceptance.py` 用于一次性 Ubuntu 测试机。需要 tcpdump；先构建源码发行包。
测试连接公开 example.com，测试代理仅用于验收，不用于生产账号。使用 --managed 额外检查专用 UID 的出口限制、DNS 丢弃计数和上游规则篡改。
它核对实际内核规则、私有 mount 和权限，抓 veth DNS 包，停止 relay 验证失败，修改 namespace 规则验证启动拒绝，然后卸载。
整个测试不得在已有部署或有活跃受保护窗口的机器运行。
自动测试不启动真实 GUI，也不登录 Claude；这两项仍需人工实机验收。

## 安装失败和恢复

安装器只改本项目命名的路径、服务、namespace、veth，以及受控模式的专用系统账号和 UID 出站表；不清空已有主机防火墙，不改全局 DNS 或系统代理。
失败时查看 systemd 日志。如果文件已安装但服务未成功启动，不要重复覆盖安装；先检查，再用卸载器清理。
namespace 与状态摘要不一致时，setup 会拒绝覆盖。不要直接删规则让应用直连。
卸载器遇到活跃 namespace 进程会拒绝操作；关闭窗口和后台任务后重试。
若存在非本项目创建的同名 namespace 或接口，必须人工识别，不能依据名字直接删除。

## v0.2 的额外验收与升级

先阅读 [上游与密钥链](UPSTREAM_AND_KEYRING.md)。本轮用户选择稍后自行 Ubuntu 测试，没有已执行的实机结果。
v0.1 已部署的机器需关闭相关进程，使用旧版卸载器移除旧部署，然后安装 v0.2；旧用户数据保留。
受控模式要求供应商支持 HTTPS CONNECT，目标端口 443；不支持此协议时选择 --external-proxy，并保留“上游未受控”的状态提示。
在正常桌面执行 `python3 scripts/keyring_acceptance.py`；默认密钥链应设置非空口令。结果中的 actual_browser_backend 仍为 not_observed，不能把通道成功当作实际存储后端验收。
检查 Chrome/Code 实际选择的存储实现与重启后的会话，记录版本。无需向助手提供密码、Cookie、Token、数据库或证件。
