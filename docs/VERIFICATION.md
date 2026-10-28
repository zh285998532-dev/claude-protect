# v0.6.0 验证记录

日期：2026-10-25（Asia/Shanghai）。开发平台：macOS，非目标运行平台。
用户明确将 Ubuntu 验收留到后面。v0.2 优化受控上游和浏览器密钥链；v0.3 增加 PySide6 面板与 Clawd；v0.4 根据用户提供的资料增加主动出口观测与本机历史、离线配置检查、20 秒滴流 / 连接复用验证、脱敏报告和五项核心保护的验收进度。没有创建测试虚拟机或声称已完成 Ubuntu 验收。

v0.5 增加独立环境检测页、一键串行流程、逐项设置建议、工作台提醒与结果有效期；不把浏览器或信誉的未知项目显示为通过。配套组件消失时清除已有在线结果，密钥链和短请求检查时间改用带时区时间戳。

v0.6 将还原入口放到连接配置与使用指南，补充清理后只读核对，并保存 root 管理的卸载脚本。不在 macOS 上执行系统还原。

已实际执行并通过：

- Python 78 项单元/本地 socket 测试：v0.5 的 73 项，加上 5 项还原核对测试，覆盖只读查询、保留其他防火墙表、兼容模式不要求不存在的上游服务、namespace / 接口 / 表 / 进程残留，以及无效或失败查询不能当作清理成功。
- PySide6 6.10.1 真实 Qt 离屏渲染与 16 项交互/进程测试：v0.5 的 12 项，加上还原确认与固定卸载器调用、检测中拒绝还原、取消确认不执行、终端结束但配置仍存在时不报已移除。已生成并查看主要页面布局。
- Node 5 项状态展示测试：普通窗口、规则失败、非 Linux/远程窗口、上游受控/外部/测试模式，以及隔离状态与账号安全的区分。
- Python 全部源码语法编译，VS Code 扩展 JavaScript 语法检查。
- 使用 Microsoft `@vscode/vsce` 4.0.0 构建 VSIX。
- 发行归档/VSIX 的文件内容和 SHA-256 校验检查。

共 99 项本地测试（78 Python + 16 Qt + 5 Node）。公开出口、滴流、一键流程和还原核对通过 mock / 模拟响应测试；没有在此 macOS 开发机上执行 Ubuntu 安装 / 还原、面向公网的真实隔离观测或 20 秒公网滴流，也没有使用 Claude 账号测试。

尚未执行，不能宣称已通过：

- Ubuntu 实际 namespace、nftables、mount、systemd 和 DNS 抓包集成测试。
- Ubuntu 22.04/24.04 桌面的官方 VS Code .deb 和 Electron sandbox 启动。
- Google Chrome .deb 的 loopback/vscode:// OAuth 路径。
- 官方 Claude Code 插件真实请求、流式连接、升级、重启后行为。
- 实际生产代理的 DNS 和上游出口。
- 专用服务 UID 在真实 nftables 中的过滤、过滤 D-Bus 的实际权限、GNOME Secret Service 与 Code/Chrome 的集成。
- Chrome 实际存储后端，以及默认 keyring 是否设置非空口令并加密保存。预检明确返回 not_observed，不当作通过。
- Ubuntu 下 Qt 的 X11/Wayland 桌面显示、系统终端/sudo 交互、应用菜单快捷方式，以及 PySide6 面板与真实服务的完整流程。
- Ubuntu 隔离环境中的 ipify 实际出口、真实代理的 20 秒 httpbin 滴流和连接复用，以及供应商远端出口是否按目标分流或轮换。
- Ubuntu 真实还原流程、systemd 服务停止 / nftables 清理、保留用户数据、活跃进程拒绝，以及普通主机网络连通性与性能。

已经提供 `scripts/linux_acceptance.py` 的外部/受控两种测试、`scripts/keyring_acceptance.py` 和 GitHub Actions 工作流，但未发布到 GitHub，也未在此环境执行 Linux 工作流。
Linux 自动测试不包含真实 GUI/账户授权。首次使用应先在可恢复的 Ubuntu 测试机验收。
