# 威胁模型与设计取舍

## 要解决的问题

用户希望本人通过官方 Claude Code 插件访问服务时，不因环境变量未继承、代理故障、IPv6、主机 DNS 或窗口复用而意外采用其他网络路径。
“账号不会被封”不可由网络组件证明，也不属于验收指标。

## 强制边界

将整个专用 VS Code 窗口放在网络命名空间，覆盖扩展宿主、自带 Claude 二进制和所有后代进程。
相较仅设置 `claudeCode.claudeProcessWrapper`，窗口级隔离还能覆盖扩展自身的请求，避免假定所有请求都经过 CLI 包装器。
代价是该窗口内其他工具也受限制。普通工作窗口用于需要主机网络的其他开发任务。

应用 namespace 只创建一个 IPv4 /30 veth 连接，不创建互联网默认路由，不开启主机转发/NAT。
v0.2 受控上游在主机新增专用 nftables 表，仅限制专用代理服务 UID，不改写或清空已有表；外部代理模式不新增此表。
namespace 内 nftables 默认丢弃，放行到指定网关地址及 relay TCP 端口的连接。
没有透明重定向、全局 TUN 或 DIRECT 备用线路。受控模式由本项目管理上游客户端；外部模式由用户管理已有代理，relay 仅复制字节。

规则在 veth 接口启用前写入。初次创建失败则清理新建对象；已存在的命名空间若和记录不一致，拒绝覆盖。
运行中不自动“修复”异常规则，不因为检测失败而放宽限制。
每次启动重新核对 namespace inode、完整 nft ruleset 摘要、主路由和地址。
状态服务是只读 root Unix socket；客户端通过 SO_PEERCRED 校验 root，服务校验安装时的用户 UID。
NoNewPrivileges 生效后不能依赖窗口内 sudo 读取防火墙，所以采用这个只读服务。

## DNS 分层

1. 应用只连接代理地址的字面 IP，不需要解析代理网关域名。
2. CONNECT 目标由代理负责；生产上游必须以域名形式继续交给远端代理，或使用明确经隧道的 DNS。
3. namespace TCP/UDP 53/853 默认阻断；DoH 直连同样没有路由/规则许可。
4. 仅阻断端口不足以覆盖 NSS：在私有 mount namespace 中替换 resolv.conf 并屏蔽 resolved、nscd、system bus。
5. v0.2 受控客户端连接字面公网 IP，将目标域名交给远端代理；其服务 UID 的其他出站被拒绝。外部代理模式仍需单独审计 bootstrap/目标 DNS。不能将主机上所有 DNS 查询都认定为 Claude 泄露，也不能靠浏览器 DNS 测试证明 CLI 安全。

## 权限与文件

安装器需要 root 创建 namespace、防火墙、systemd unit 和受限 sudo 入口。
sudoers 仅允许固定 helper 的 `run` 子命令。helper 只接受预设 code/install/probe 模式，UID 来自 sudo 和 root 配置；不接受任意 root 命令或调用方提供的 UID。
在执行用户应用前进入 namespace、创建私有 mount、丢弃全部 capabilities，设置 NoNewPrivileges，再切换到安装时的用户。
私有挂载不改变主机文件内容，不删除账户配置。

不支持 root 用户运行、Snap/Flatpak VS Code、不支持 --no-sandbox 兜底。
root 配置及其所有父路径必须由 root 拥有且不可被组/其他用户写入。
公开配置仅包含 UID、端口、子网、固定 Code 路径和上游策略，不存密码或 Claude Token。
受控上游的代理认证单独放在 root:专用服务组的 0640 文件中，不允许密码命令行参数。没有 Claude 账号凭据的代理购买/采集流程。
转发器不解密 TLS，不记录 CONNECT 内容、认证头、请求体、代码或聊天。

## 不提供的保证

不防御已控制宿主机的 root。管理员可以改 namespace、防火墙、状态服务和代码。
这不是恶意代码沙箱：用户文件和部分 Unix/display IPC 仍可访问；不能证明恶意进程不会委托外部可用服务联网。
依赖系统/VS Code/Claude 官方二进制。程序升级后需重新做端到端验证。
不以 GeoIP 或住宅 IP 分数推断平台的账户安全状态。
v0.2 只通过方法/路径受限的 Secret Service D-Bus 代理访问密钥链，保持原始会话总线和解析接口屏蔽。
预检库/通道/解锁状态不等于实际浏览器后端或 keyring 磁盘加密证明；这些仍由 Ubuntu 实机验收。
不伪装设备标识，不复制/轮换账号凭据，不阻断遥测来声称防封，不伪造健康检查。

## 验证层次

- 单测：配置拒绝、权限边界、规则篡改识别、字节转发、上游失败、状态展示。
- Linux 集成：实际 namespace/nft/mount、DNS 包、正常代理、断线、篡改和恢复。
- Ubuntu 桌面验收：真实 VS Code .deb、官方插件自带进程、Electron sandbox、首次 OAuth 和会话恢复。

缺少后两层时只能交付待验收版本，不能宣称已在 Ubuntu 实现零泄露。
