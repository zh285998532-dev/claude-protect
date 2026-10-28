# Claude Protect

面向 **Ubuntu 桌面 + VS Code 官方 Claude Code 插件 + 本人 Pro/Max 账号** 的网络保护项目。
交付一个 VS Code 扩展、配套 Linux 组件，以及可选的 **Python / PySide6 中文控制面板**。面板采用暖白 / 陶土橙配色与 Claude Code 的 Clawd 像素形象，提供图形化配置、启动、检查与日志。强制出站限制由 Linux 内核完成。

**v0.6.0 是待 Ubuntu 实机验收的版本。** v0.2 优化受控上游与浏览器密钥链，v0.3 新增 PySide6 面板，v0.4 增加主动诊断与脱敏报告，v0.5 增加环境检测与设置提醒，v0.6 增加显式还原入口与清理核对。Ubuntu 测试由用户稍后执行。当前开发机为 macOS，本地测试和界面渲染不代表 Linux 内核/桌面/OAuth 集成已通过。
本项目控制网络路径，不承诺防封效果，不伪装设备身份，不修改 Claude 二进制，不模拟服务端检查成功。
服务适用地区、身份、支付和使用规则仍由 Anthropic 决定。

## 工作方式

```text
独立 VS Code 窗口（官方 Claude 插件、集成终端、工具子进程）
  └─ 独立网络 namespace + 私有 resolver 挂载 + 无提权能力
       └─ 唯一出站：10.254.253.1:19080
            └─ 不解密 TLS 的 TCP relay
                 └─ 主机 127.0.0.1:20808 的内置 CONNECT 客户端
                      └─ 独立服务 UID 的出站规则 → 唯一公网 IP:端口
                           └─ 经 TLS 验证的远端代理 → 目标服务（远端解析）
```

- namespace **没有互联网默认路由**；nftables 默认丢弃，只允许本地 loopback 和指定代理入口。
- IPv6 仅在该 namespace 内禁用；TCP/UDP 53 和 853 均阻断，包括 loopback DNS。
- 私有挂载替换 `/etc/resolv.conf`，屏蔽常见 `systemd-resolved`、D-Bus、nscd 解析接口，避免委托主机查询。
- 代理不可用、relay 退出或状态核对失败时不回退直连。
- VS Code 使用独立 user-data/extensions 目录，不复用已有普通窗口；启动时检查误在外部运行的同一 profile。
- 运行进程为桌面用户，丢弃 capabilities，启用 `NoNewPrivileges`。不关闭 Chromium sandbox。
- 状态插件核对 namespace 身份、nftables 摘要、路由、私有 resolver 挂载和进程权限；不把“代理配置存在”显示为保护成功。
- 每 15 秒只读检查。联网探测由用户主动启动，不读取账号凭据，不发送提示词或代码。
- 受控上游模式只允许专用服务 UID 连接一个远端 IPv4:端口；没有本地目标 DNS、DIRECT 或备用出口。主机只新增本项目的专用 nftables 表，不清空既有规则。
- Secret Service 通过 `xdg-dbus-proxy` 的方法/路径白名单提供；不开放解析器、systemd、门户或整个桌面 D-Bus。默认密钥链不可用或锁定时阻止 GUI 启动。
- 显式请求 `gnome-libsecret`；预检不读取密码/Cookie，也不把“服务可用”声称为 Chrome 实际后端或磁盘加密已验证。

**边界：**此窗口里的其他扩展、终端和工具也受限；Git SSH、主机数据库、主机 loopback MCP 默认不可达。
窗口内自行启动的 loopback 开发服务可用。普通 VS Code 窗口和主机网络保持原样。
提供同一隔离环境内的授权浏览器入口（Google Chrome 官方 .deb），并用专用 XDG MIME 配置把官方 vscode:// 回调送回受保护窗口。
不修改主机默认浏览器，不伪装浏览器指纹。浏览器/授权集成仍需实机验收；见 [部署与验收](docs/DEPLOY.md)。

## 图形界面（推荐入口）

解压 `claude-protect-0.6.0-ubuntu.tar.gz` 并进入目录，在普通 Ubuntu 桌面用户的终端执行：

```bash
sudo apt update
sudo apt install python3-venv libxcb-cursor0 libegl1 libxkbcommon-x11-0
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-gui.txt
.venv/bin/python scripts/gui.py
```

进入「连接配置」，安装依赖并填写代理参数，再点击安装系统组件。管理员密码与代理认证只在弹出的系统终端输入。
组件就绪后，安装两个插件，在工作台选择项目并打开 VS Code，或打开受保护 Claude 网页。
可以从「使用指南」将面板添加到应用菜单；保留解压目录与虚拟环境即可日常点击启动。

其他平台可以运行 `python scripts/gui.py --demo` 查看界面；演示模式禁用系统操作，明确显示未连接系统。
参见 [完整图形界面说明](docs/GUI.md)。Clawd 角色与第三方依赖归属见 [NOTICE](NOTICE.md)。

「诊断与日志」展示 DNS 防旁路、IPv6 约束、代理路径、断线阻断和流式通道五项进度；区分已有实现与本次实测通过。
主动出口观测与滴流样本只有点击按钮时才联网，不使用 Claude 账号。离线检查只覆盖面板自身环境，脱敏报告不包含凭据或原始日志。
固定代理入口不保证远端出口固定，第三方检测分数不作为官方判定。详见 [网络保护与诊断说明](docs/NETWORK_DIAGNOSTICS.md)。

「环境检测」提供一键串行检查、逐项结果和「接下来怎么设置」入口，并在工作台提醒待处理项。
近期且有正向对照的结果才显示通过，过期结果提醒重测；浏览器 WebRTC、IP 信誉和使用资格保持未自动验证，可打开受保护 Net.Coffee 页面继续核对。
详见 [环境检测与设置提醒](docs/ENVIRONMENT_CHECK.md)。

## Ubuntu 命令行安装

目标为 Ubuntu 22.04/24.04 桌面，systemd，官方 **.deb** 版 VS Code。Snap/Flatpak、Remote SSH、容器桌面暂不列入支持范围。
“目标”不等于已验收；先在测试机器运行下面的验收流程。

安装依赖（不会由 VS Code 扩展自动执行）：

```bash
sudo apt update
sudo apt install python3 iproute2 nftables util-linux sudo xdg-dbus-proxy libglib2.0-bin libsecret-1-0 gnome-keyring
```

先安装 Microsoft 官方 .deb 版 VS Code，并准备支持 **HTTPS CONNECT（HTTP/1.x）** 的远端代理。
生产受控模式要求代理服务器公网 IPv4，TLS 证书正常验证；TLS 域名只用于 SNI/证书校验，不用于本地解析。
内置客户端目前仅允许目标 HTTPS 的 `hostname:443`，不支持 SOCKS、明文目标 HTTP 或其他目标端口。
已有的本地 sing-box/Mihomo 可以通过明确的外部代理模式继续使用，但该模式不能显示“上游已受控”。
详见 [上游与密钥链设计](docs/UPSTREAM_AND_KEYRING.md)。

在已解压的项目目录中：

```bash
# 替换成你已有代理的真实公网 IPv4 和证书域名；不要填写 Claude 账号凭据。
PROXY_IPV4='替换为代理公网IPv4'
PROXY_TLS_NAME='替换为代理证书域名'
sudo python3 scripts/install.py --user "$(id -un)" \
  --upstream-ip "$PROXY_IPV4" --upstream-port 443 \
  --upstream-tls-name "$PROXY_TLS_NAME" --upstream-auth

# 以下命令使用普通桌面用户，不要加 sudo。
claude-protect install-plugin
claude-protect install-official
claude-protect launch /你的/项目绝对路径

# 首次登录需要时：先安装官方 Google Chrome .deb，再打开受保护浏览器。
claude-protect browser https://claude.ai/
```

`--upstream-auth` 在本机终端安全提示读取代理密码；匿名上游可省略。安装器创建专用服务账号，凭据文件仅 root 和该服务组可读。
GUI 启动前请在 Ubuntu 桌面解锁默认密钥链。首次启动会启动用户级过滤服务。
若只能使用已有本地代理，安装时明确指定 `--external-proxy --proxy-port 20808`，不再填 `--upstream-*` 参数。
升级已安装的旧版系统组件时，需先关闭受保护进程、用旧版卸载器卸载，再安装新版；不自动覆盖运行中的防火墙或迁移凭据。新版源码面板所用诊断命令兼容 v0.4 及后续系统组件。

也可以从应用菜单选择 **Claude Protect — VS Code**。
必须在新打开的受保护窗口中使用官方 Claude Code 插件。
只安装 VSIX 到普通窗口不会改变那个窗口的网络权限。

插件命令：

- `Claude Protect: 查看隔离状态`
- `Claude Protect: 打开受保护窗口`
- `Claude Protect: 打开受保护浏览器`
- `Claude Protect: 检查密钥链通道`
- `Claude Protect: 运行联网验证`
- `Claude Protect: 打开使用说明`

状态区分“双层出站已核对”“上游未受控”和“测试上游”；都不代表账号安全或代理始终可达。代理是否可用由 `claude-protect probe` 单独测试。
该测试通过代理连接 `example.com:443` 并验证 TLS，同时检查直接 IPv4/IPv6、DNS 和额外主机端口不可达。
它不登录 Claude，不消耗账号额度，也不能代替 DNS 抓包验收。

额外诊断命令（普通用户运行）：

```bash
claude-protect audit         # 离线：当前进程环境，不输出密钥或原始代理 URL
claude-protect egress        # 主动联网：隔离内向 ipify 发出两次 HTTPS 请求
claude-protect stream-check  # 主动联网：隔离内的约 20 秒 httpbin 滴流样本
```

出口观测不证明 Anthropic 实际出口；通用滴流样本不代表真实 Claude SSE / WebSocket 已验收。

## 日常浏览器登录与网页版

可以日常使用 Claude 网页版，不限于 VS Code 的授权流程。安装官方 Google Chrome .deb 后，使用应用菜单的
**Claude Protect — 受保护浏览器**、VS Code 的“打开受保护浏览器”命令，或运行：

```bash
claude-protect browser https://claude.ai/
```

浏览器与受保护 VS Code 使用同一 namespace 和代理入口，受相同的 DNS、IPv6 和断线限制。
它使用独立、持久的 Chrome profile：首次由本人完成登录，之后正常保留会话；不自动导入普通浏览器的 Cookie、密码或扩展。
v0.2 使用 `~/.local/share/claude-protect/browser-v2/`，不自动复用旧版 `browser/`，旧数据保留。这样不会把未核查存储后端的旧会话默默带入新版。
关闭 VS Code 后仍可通过此入口单独启动浏览器。使用完毕正常关闭窗口即可，不需要每次清 Cookie 或重新登录。

普通 Chrome/Firefox 快捷方式不会自动进入保护环境；日常访问 Claude 应从上述入口打开。
不要从普通浏览器手动打开受保护 profile。此 profile 已在隔离外运行时，启动器会拒绝复用。
登录和验证均由本人完成；不需要改语言、时区或浏览器指纹。Ubuntu 上需分别验收网页版、第三方登录跳转、授权回调、WebSocket/流式响应和断线行为。

## 重要限制

- 受控模式的本机 CONNECT 客户端只连接固定上游并把域名交给远端解析；远端代理自己的基础设施仍由供应商控制。外部代理模式的 DNS/出口需要你另外审计。
- 受控模式新增 `inet claude_protect_upstream`，只匹配专用服务 UID；不清空/改写已有表。既有 UFW/nftables 仍可能阻断连接，不能自动放宽它们。
- 密钥链预检检查库、过滤通道、默认 collection 和锁定状态，不证明 Chrome 实际已选择该后端，也不证明默认 keyring 设置了非空口令；需按密钥链验收说明检查。
- 受保护窗口依然能访问该用户原本可读写的文件。此项目不是用于运行恶意代码的完整文件/IPC 沙箱。
- 显示服务器 socket 和部分开发 IPC 仍可访问；恶意代码可能委托外部进程联网。常见 resolver 和 Docker/Podman socket 会屏蔽，但不声称覆盖所有 IPC。
- 普通窗口、外部浏览器、外部 MCP 服务、主机上的其他客户端不在本项目的保证范围。请使用配套受保护浏览器完成授权。
- 代理会看到连接元数据。不要使用需要你交出 Claude Cookie、Token、MFA 或安装解密证书的中转。
- 不允许通过本项目绕过服务资格限制，也不提供账号关联规避、指纹伪装、养号或健康检查造假功能。

## 测试和构建

Python 和 VS Code 扩展没有 pip/npm 运行依赖；Linux 集成依赖上面的系统包。测试不需要账号或真实代理凭据。

```bash
PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/status.test.js

# 可选：已安装 PySide6 时，执行真实 Qt 离屏渲染与交互测试。
QT_QPA_PLATFORM=offscreen python tests/gui_smoke.py

# 发行打包时使用微软的 vsce；下面的脚本不执行网络安装。
python3 scripts/build.py --vsce /path/to/vsce
```

Linux 上的完整网络验收：仅在可恢复的 Ubuntu 测试机/CI runner 中执行：

```bash
sudo python3 scripts/linux_acceptance.py --user "$(id -un)"
sudo python3 scripts/linux_acceptance.py --user "$(id -un)" --managed

# 普通、已登录的 Ubuntu 桌面终端，不能 sudo：
python3 scripts/keyring_acceptance.py
```

它会安装测试用系统组件、启动本机测试 CONNECT 代理、核对 DNS 抓包、测试 relay 停止和 firewall 被修改后的行为，最后卸载。
不能在已有 Claude Protect 部署或正在工作的桌面上运行。详见 [验收说明](docs/DEPLOY.md)。

## 还原系统配置 / 卸载

普通应用沿用原来的主机网络；保护窗口通过代理，其速度受代理节点和共享资源影响，尚未进行 Ubuntu 性能基准测试。
「连接配置」顶部提供「还原系统配置」按钮，页面底部列出移除与保留范围，「使用指南」也有同一入口。
先停止检测并关闭受保护 VS Code / Chrome，再在系统终端确认管理员权限。

还原会移除本项目的 namespace、接口、服务、专用规则、sudo 授权和受控代理凭据；保留项目、Claude 登录资料、专用窗口数据与外部代理配置。它不重置主机全局网络或外部代理的 TUN / 全局开关。
清理后核对专用网络残留与系统服务，无法确认时不宣称还原完成。详见 [网速影响与还原说明](docs/RESTORE.md)。

关闭受保护窗口及其所有后台进程，然后在源码目录运行：

```bash
sudo python3 scripts/uninstall.py
```

默认保留 `~/.local/share/claude-protect/`、官方 Claude 登录数据、项目文件和用户自己的外部代理。移除本项目创建的上游服务、其专用规则和凭据文件；专用系统账号仅在本项目创建时删除。
还有活跃保护进程时拒绝卸载，不会先移除限制。安装失败的恢复步骤见部署文档。

## 设计依据

- [Claude Code 官方代理配置](https://code.claude.com/docs/en/network-config)
- [官方 VS Code 插件及独立 CLI 的关系](https://code.claude.com/docs/en/vs-code)
- [systemd-resolved 的 DNS 与本地 IPC 接口](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html)
- [威胁模型与设计取舍](docs/THREAT_MODEL.md)
- [上游与密钥链实现、限制和验收](docs/UPSTREAM_AND_KEYRING.md)

本项目独立开发，与 Anthropic、Microsoft 无隶属关系。MIT License。
