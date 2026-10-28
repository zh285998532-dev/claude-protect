# Claude Guard 与 Claude Protect 的保护边界比较

核对日期：2026-10-26。以下是只读源码比较，未安装或执行外部项目。

## 先区分同名项目

用户尚未提供具体链接，因此不能确定所指仓库：

- [carycheung/claude-guard](https://github.com/carycheung/claude-guard)：macOS 菜单栏网络守护，依赖 Clash Verge Rev，主要保护 Claude 桌面应用。快照：`7511bec5989fd5c1969092ea253e184966bd74e9`。[README](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/README.md)
- [wetlink/claude-guard](https://github.com/wetlink/claude-guard)：官方 Claude Code 的启动门禁、独立配置与运行观察；运行看门狗记录预期暂停/恢复动作，不实际暂停或终止进程。快照：`767a263243a2e0350541780f5f722f90be0c1400`。[README](https://github.com/wetlink/claude-guard/blob/767a263243a2e0350541780f5f722f90be0c1400/README.md)
- [hex/claude-guard](https://github.com/hex/claude-guard)：拦截破坏性命令和凭据暴露的 Claude Code 插件，主题与网络隔离不同。快照：`51edf72f630a5d74cbd27a310e342bff551feaba`。[README](https://github.com/hex/claude-guard/blob/51edf72f630a5d74cbd27a310e342bff551feaba/README.md)

## 与 macOS 网络守护版本的比较

共同目标是发现异常网络路径并减少意外直连；具体机制不同：

| 方面 | carycheung/claude-guard | 本项目 Claude Protect |
| --- | --- | --- |
| 保护对象 | 指定 bundle ID 的 Claude 桌面应用 | 从专用入口启动的整个 VS Code 窗口、后代进程和受保护 Chrome |
| 网络边界 | 依赖主机 TUN；周期检测后退出 Claude | 应用网络命名空间无互联网默认路由，nftables 默认拒绝，只允许连接指定 relay |
| 故障处理 | 5 秒定时快检，失败复测后请求退出，3 秒后强制退出；尝试恢复代理 | 不因检测失败放宽隔离规则；relay 不提供直连备用线路 |
| DNS | 所读检测代码未专项验证目标 DNS 的解析策略与传输路径 | 阻断应用侧直连 DNS、屏蔽主机解析接口；外部代理自身的 DNS 仍需另查 |
| 浏览器 | 宿主 Python STUN 探针；不等于真实浏览器 ICE 检测 | 独立 Chrome profile 在相同隔离中启动；浏览器环境和测试证据另行验证 |

外部项目依据：[主程序](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/main.swift)、[STUN 探针](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/stun_check.py)。本地依据：[威胁模型](THREAT_MODEL.md)、[kernel.py](../lib/claude_protect/kernel.py)、[relay.py](../lib/claude_protect/relay.py)、[browser.py](../lib/claude_protect/browser.py)。

上述区别由源码推得：周期检测和退出进程之间存在检测、请求超时及退出等待时间，不能解释成内核即时阻断。主程序快检只检查 TUN、出口地区和无凭证 API 响应，并非每轮执行所有完整检测项。[快检与退出实现](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/main.swift#L491-L557)

## 不能照搬的判定

- STUN 无结果可能来自探针错误、超时或服务不可达；不能单凭空结果证明浏览器不存在 UDP 泄露。[探针的异常处理](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/stun_check.py#L31-L41)
- 无凭证请求返回认证错误，只说明该次请求获得此类响应；不能证明账号权限、地区资格或未来使用结果。[API 探针](https://github.com/carycheung/claude-guard/blob/7511bec5989fd5c1969092ea253e184966bd74e9/main.swift#L170-L173)
- 普通 IP 查询站与 Claude 可能命中不同分流策略。wetlink 选择官方 API 域名的 trace 端点，并说明负载均衡时同策略也不必然同出口。[出口探测说明](https://github.com/wetlink/claude-guard/blob/767a263243a2e0350541780f5f722f90be0c1400/README.md#L289-L297)

## 当前 DNS 提示意味着什么

本项目的外部代理检查读取可取得的 DNS 配置，调用核心 DNS 查询接口，并在 Claude 查询失败后查询对照域名。修复前观测到运行配置未明确设置 `respect-rules`、节点解析器未明确配置、Claude 查询超时而对照成功；这些证据不能单独证明已经泄露。[external_audit.py](../lib/claude_protect/external_audit.py)

2026-10-26 21:49（Asia/Tokyo）完成本机修复：先验证经现有代理访问 Cloudflare DoH 能解析 Claude，再备份配置，启用 DNS 遵从现有路由、沿用既有解析器单独解析节点，并为 Claude/Anthropic 域名设置经 GLOBAL 的 DoH。管理员脚本应用后核对 DNS、节点、模式和 TUN，失败自动回滚。本机外部代理五项检查及隔离内十一项探测均通过；属于本次配置与抽样验证，不是全部流量抓包或上游故障注入证明。[修复脚本](../scripts/repair_external_dns.py)、[DNS 指定代理文档](https://wiki.metacubex.one/config/dns/#dns-指定-代理接口-进行连接)

外部代理模式仍由 Clash 决定代理自身的 DNS、DIRECT 与出口；本项目受控上游模式才另对专用上游服务 UID 限制出站。任何版本都不能保证账号不受限制。[威胁模型](THREAT_MODEL.md)、[upstream_policy.py](../lib/claude_protect/upstream_policy.py)
