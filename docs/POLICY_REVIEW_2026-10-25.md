# Claude Protect 官方规则与改进评估

核查日期：2026-10-25（Asia/Shanghai）。这是规则与设计审查，下面的待办不代表已经实现。

后续实施记录：用户明确将 Ubuntu 实测留到后面，要求先优化第二、第三项。v0.2 已新增受控上游 UID 出站规则、远端 CONNECT、过滤 Secret Service、库/通道/解锁预检，并修正自然 locale 传递；见 [实现与剩余边界](UPSTREAM_AND_KEYRING.md)。以下保留 v0.1 审查时的缺口，实际浏览器存储后端仍未实测。

## 结论

当前方案有助于约束网络路径，但不是已经验证的账号防封方案。
最高优先级是 Ubuntu 端到端验收、主机代理自身的 DNS/出口约束、浏览器凭据存储与授权兼容性。
增加指纹伪装、账户轮换或“住宅 IP 安全分”没有可靠的防封效果依据。

## 官方规则与网络传言的区别

### 1. 地区资格优先于出口地址

官方消费者条款要求遵守支持地区规则；支持地区列表当前没有中国大陆。
封禁帮助页列出了不支持地区注册、重复违反使用政策和违反条款等原因。
代理出口的国家或 GeoIP 评分不能证明用户实际具备服务资格，也不能据此保证账号安全。

来源：[消费者条款](https://www.anthropic.com/legal/consumer-terms)、[支持地区](https://support.claude.com/en/articles/8461763-where-can-i-access-claude)、[警告与申诉](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals)。

### 2. 本人使用官方网页与官方 Claude Code 是正常产品用法

官方支持用同一 Pro/Max 订阅访问网页与支持 IDE 中的 Claude Code，使用额度共享。
多设备本人登录也有官方支持说明。不能把“本人网页加 VS Code 使用”直接认定为共享账号或封禁触发器。
消费者条款禁止把账号、登录信息或凭据共享给他人。

来源：[Pro/Max 与 Claude Code](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan)、[官方登录帮助](https://support.claude.com/en/articles/13189465-log-in-to-your-claude-account)、[消费者条款](https://www.anthropic.com/legal/consumer-terms)。

### 3. 第三方工具应区分认证、用途和计费

不能笼统写成“所有第三方工具都违规”。官方登录帮助说明，第三方工具优先使用 API key 或支持的云提供商；某些第三方工具可能经官方允许从 usage credits 计费。
假冒客户端身份、试图把第三方流量计入不适用的订阅额度、收集或中转 Claude 凭据都存在明确限制。
当前 Protect 应维持官方客户端不修改、本人完成官方登录、opaque CONNECT 转发、不解密 TLS、不接收账号 Token 的设计。

来源：[登录与订阅认证规则](https://support.claude.com/en/articles/13189465-log-in-to-your-claude-account)、[Claude Code 认证与凭据规则](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use)。

### 4. 限流、错误和封号不是同一件事

网页与 Claude Code 共享额度。达到额度、服务容量问题、网络断开、登录失败和正式停用应分别解释。
不通过换账号、假冒客户端、代理池轮换或无限重试来处理额度问题。
也不因为正常多会话或单次 403/429 就自动判定账号被封；以官方页面、账户通知和支持渠道为准。

来源：[Pro/Max 使用限制](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan)、[错误说明](https://support.claude.com/en/articles/12466728-troubleshoot-claude-error-messages)。

### 5. 验证由本人完成

官方已说明某些能力、平台完整性检查或合规措施可能触发身份验证，使用 Persona，可能需要本人有效实体证件和自拍。
不能承诺购买某种 IP、Google 登录或充值前等待若干小时就能免验证，也不能从证件可被接受推导出地区资格。
手机扫码验证不受 Ubuntu 网络 namespace 保护，需单独核对实际环境；本项目不自动完成验证或收集证件。

来源：[身份验证说明](https://support.claude.com/en/articles/14328960-identity-verification-on-claude)。

### 6. 常见“防封技巧”的证据等级

| 网上建议 | 本次判断 |
| --- | --- |
| 自己的账号、官方客户端、按规则使用 | 有官方依据 |
| 明确代理/DNS 路径、断线阻断 | 可验证的网络控制；没有已证实的封号率收益 |
| 固定出口、避免调试时反复换线路 | 便于诊断；不应宣传成平台强制要求或免封保证 |
| 必须住宅 IP、特定风险分数才安全 | 本次未找到官方防封阈值或保证 |
| 改英文、改时区、随机硬件标识 | 本次未找到降低封禁概率的官方依据 |
| 注册后等 72 小时、“养号”制造互动 | 本次未找到官方依据 |
| 每次登录都清 Cookie | 官方只在特定登录排障中建议清缓存/Cookie；不应变成日常强制动作 |
| 所有 VPN 都会封 / 使用代理必定更安全 | 都不能从官方资料推出；官方登录排障反而建议检查 VPN 是否造成问题 |

来源：[官方网络配置](https://code.claude.com/docs/en/network-config)、[官方登录排障](https://support.claude.com/en/articles/12466728-troubleshoot-claude-error-messages)。
未找到依据不代表能够证明完全没有影响，只表示本项目不应将其当作已验证的防封功能。

## 对照当前代码的改进优先级

### P0：日常使用前需要解决/验收

1. **完成 Ubuntu 的实际网络与桌面验收。** 本地单测目前不能证明 namespace、nftables、AppArmor/Electron sandbox、重启恢复、流式连接断开、实际 DNS 路径正确。已有 Linux 验收脚本和 CI 配置，但尚未运行于目标环境；真实官方插件/Chrome/登录流程仍须单独验收。
2. **把主机代理本身纳入保证范围。** 当前只限制受保护窗口到 relay 的路径，relay 再转发至用户管理的 127.0.0.1 代理。该代理仍可能直连 DNS、配置 DIRECT 分支或切换上游。需要可选的受控代理实例、固定配置核验、上游字面 IP/必要 bootstrap DNS 设计，以及在单独网络边界中限定其实际出口。不是单纯加一个“住宅 IP 分数检查”。
3. **核查 Linux 浏览器的安全凭据存储。** 当前屏蔽 session/system D-Bus 以阻止 resolver/IPC 旁路，可能同时影响 Chrome 的 Secret Service/KWallet。Chromium 官方说明不可用时可能回退 basic 明文存储。这里是风险推断，尚未实机观察，不应直接宣布已发生。必须测出实际 store；需要支持时设计仅允许必要接口的 D-Bus 代理，不整体放开宿主总线，不添加 --password-store=basic 兜底。
4. **浏览器、VS Code 与手机分别核验。** VS Code 状态栏不能代表任意 Chrome 窗口已隔离。需要对实际 browser PID 检查 namespace、capabilities、resolver mount 和 profile，实测网页请求/流式回复/断线。手机认证仍属于外部设备，不能标成已经保护。

凭据存储来源：[Chromium Linux Password Storage](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/password_storage.md)。

### P1：下一轮代码改进

5. **保留自然语言环境。** 当前 `helper.py::app_environment` 固定 `LANG=C.UTF-8`；应保留用户已有、经允许列表传递的 LANG/LANGUAGE/LC_*，系统工具稳定输出的 locale 与用户应用 locale 分开。无需伪装语言、时区或地理位置。
6. **单独显示“隔离正常”和“上游可达”。** 不以端口监听/连通测试推断出口位置或账号状态。联网检查应由用户主动触发或清楚配置，避免默默把连接元数据发给第三方 IP 检测站。
7. **增加只读、脱敏诊断导出。** 可包含版本、namespace、规则摘要、检查结果和时间；排除 OAuth URL、Cookie、Token、提示词、源码、证件和代理凭据。错误分类以可观察事实为准，不解析/绕过账号风控。
8. **完善升级与回归。** 记录官方 Code/插件/Chrome、内核和代理版本；更新后重新检查规则和受保护进程，支持可恢复的包升级，避免通过重装删除既有会话。

### P2：文档与交互

9. 首次配置清楚链接官方地区、认证、额度、身份验证和申诉说明；注明规则检索日期，不把 GeoIP 当作用户实际所在地，也不收集证件或精准位置来“自动判资格”。
10. 日常入口保持简单：一个受保护 Code 入口和一个受保护浏览器入口；持久保留正常会话，退出/清理作为明确的用户操作，不自动制造互动或定时重登。

## 日期与证据限制

本次打开的 Usage Policy 页面显示生效日为 **2026-11-12**，晚于本次核查日；支持地区政策新版也可能有未来生效日。
不能把未来版本当作 2026-10-25 已生效的规定。本报告关于账号、地区、认证与额度的结论使用消费者条款和官方帮助页；不将未来 AUP 的新增细节写成现行要求。
官方还有 [2025-08-15 的使用政策更新公告](https://www.anthropic.com/news/usage-policy-update)，说明该轮更新于 2025-09-15 生效，但该公告不能替代完整政策版本。
社区个案缺少完整账户背景与对照数据，不能用来给 IP 类型、浏览器指纹或使用时长计算可靠的封禁概率。

## 建议实施顺序

Ubuntu 测试环境 → 完整内核/桌面/登录验收 → 主机代理和 DNS 边界 → 浏览器凭据存储/IPC → 自然 locale → 状态与脱敏诊断 → 升级回归。

这里是设计和代码改进建议；未执行的 Linux/GUI/账号验证仍标记为未验证。
