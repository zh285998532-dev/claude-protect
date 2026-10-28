"""Evidence-based checklist and setting suggestions; never a ban-risk score."""
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone

from .diagnostics import EGRESS_TARGET, STREAM_TARGET, timestamp

LABELS = {"pass": "本次通过", "fix": "需要处理", "warn": "需要核对", "pending": "尚未验证"}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    state: str
    evidence: str
    advice: str
    action: str


def fresh(result, now=None, max_age=600):
    try:
        checked = datetime.fromisoformat(result["checked_at"])
        if checked.tzinfo is None:
            return False
        age = ((now or datetime.now(timezone.utc)) - checked).total_seconds()
        return -30 <= age <= max_age
    except (KeyError, TypeError, ValueError):
        return False


def checklist(*, installed=False, status=None, status_checked_at=None, keyring=None,
              probe=None, audit=None, egress=None, streaming=None, upstream=None, now=None, preview=False):
    status, probe, keyring = status or {}, probe or {}, keyring or {}
    audit, egress, streaming = audit or {}, egress or {}, streaming or {}
    rows = []

    def add(identifier, title, state, evidence, advice, action):
        rows.append(Check(identifier, title, state, evidence, advice, action))

    current = fresh({"checked_at": status_checked_at}, now, max_age=45)
    ready = installed and current and status.get("kernel_ok") is True
    if not installed:
        add("installation", "配套组件与隔离", "fix", "未发现系统配置。", "先配置代理并安装系统组件，再安装两个 VS Code 插件。", "configure")
    elif not ready:
        add("installation", "配套组件与隔离", "fix" if current else "pending",
            "本次内核核对未通过。" if current else "缺少最近 45 秒内的隔离状态。",
            "刷新隔离状态，查看诊断日志；不要把普通 VS Code 窗口当作受保护窗口。", "refresh")
    else:
        add("installation", "配套组件与隔离", "pass", "最近一次内核规则与命名空间核对通过。",
            "继续从专用入口打开工作窗口。", "diagnostics")
    if not ready:
        add("upstream", "代理自身的 DNS / 出口", "pending", "隔离未就绪，不能确认实际策略。", "先处理隔离与安装状态。", "configure")
    elif status.get("upstream_test_only") is True:
        add("upstream", "代理自身的 DNS / 出口", "fix", "当前使用测试上游。", "关闭受保护应用，按说明卸载后改用经过 TLS 验证的正式上游。", "configure")
    elif status.get("upstream_managed") is not True:
        from .external_audit import checks_passed
        tested = fresh(upstream or {}, now) and upstream.get("status") == "complete"
        items = upstream.get("items", []) if tested else []
        problems = any(item.get("state") == "fix" for item in items)
        complete = checks_passed(upstream, now)
        evidence = "本次外部代理检测发现 DIRECT 路径。" if problems else "本次代理识别、测试连接、DNS 配置/解析、出口和回退配置五项通过。" if complete else "已自动检测；具体通过项、配置提示与未能验证原因见诊断页。" if tested else "尚未取得最近 10 分钟内的外部代理检测结果。"
        advice = "仅代表本次配置与抽样检查；不等于强制约束外部代理，也不代替 DNS 抓包或上游故障注入。切换节点后重新检测。"
        if not complete:
            advice = "点击检测，核对代理软件的 DNS、DIRECT 与自动回退配置。" + advice
        add("upstream", "代理自身的 DNS / 出口", "fix" if problems else "pass" if complete else "warn", evidence,
            advice, "upstream")
    else:
        add("upstream", "代理自身的 DNS / 出口", "pass", "专用代理服务 UID 的固定入口规则已核对。",
            "供应商最终出口仍需观测；固定入口不代表固定最终出口。", "egress")
    probe_current = ready and fresh(probe, now)
    control = probe_current and probe.get("passed") is True and all(probe.get("checks", {}).get(key) is True
                for key in ("proxy_tls_verified", "namespace_matches", "runtime_isolated", "runtime_isolated_after"))
    for identifier, title, keys in (
        ("dns", "应用侧 DNS 防旁路", ("udp_dns_denied", "tcp_dns_denied", "dot_denied", "system_dns_denied")),
        ("ipv6", "隔离内 IPv6 约束", ("direct_ipv6_denied",)),
        ("connectivity", "代理连通与直连阻断", ("direct_ipv4_denied", "runtime_isolated", "runtime_isolated_after")),
    ):
        if control and all(probe.get("checks", {}).get(key) is True for key in keys):
            add(identifier, title, "pass", "本次主动探测与 HTTPS 正向对照通过。",
                "仅代表本次应用侧探测，DNS 抓包与浏览器检查仍需单独执行。", "probe")
        elif probe_current:
            add(identifier, title, "warn", "本次联网验证未完整通过，不能据此断言发生泄露或账号被封。",
                "检查代理是否运行、端口与 TLS 是否正确，再重新验证。", "probe")
        else:
            add(identifier, title, "pending", "缺少当前隔离策略下最近 10 分钟内的探测结果。",
                "隔离就绪后运行联网验证；不会自动关闭主机全局 IPv6。", "probe")
    if ready and fresh(keyring, now):
        if all(keyring.get(key) is True for key in ("available", "default_collection_unlocked", "filtered_bus")):
            add("keyring", "桌面密钥链通道", "pass", "本次过滤通道可用，默认密钥链已解锁。",
                "服务可用不证明浏览器实际存储后端或磁盘加密已验收。", "keyring")
        else:
            add("keyring", "桌面密钥链通道", "fix", "本次密钥链预检未通过，GUI 启动器会拒绝放行。",
                "在 Ubuntu「密码和密钥」中创建并解锁默认密钥链，再重试通道检查。", "keyring-settings")
    else:
        add("keyring", "桌面密钥链通道", "pending", "缺少最近 10 分钟内的通道预检。",
            "检查密钥链通道；有锁定提示时打开「密码和密钥」。", "keyring")
    if ready and fresh(egress, now) and egress.get("target") == EGRESS_TARGET:
        if egress.get("status") != "complete":
            add("egress", "实际出口与变化", "warn", "本次出口观测未完整完成。",
                "检查代理或检测服务后重新观测；不能沿用旧 IP 作为本次结果。", "egress")
        elif egress.get("stable_during_sample") is not True or egress.get("changed_since_previous") is True:
            add("egress", "实际出口与变化", "warn", "两次采样不同，或与上次同配置观测存在变化。",
                "核对代理供应商是否轮换或按目标分流，先确认原因，不自动切换节点。", "egress")
        else:
            add("egress", "实际出口与变化", "pass", "本次两次采样相同；不代表长期稳定或 Anthropic 的实际出口。",
                "保留本机历史供下次比较；检测站结果只覆盖其自身所见。", "egress")
    else:
        add("egress", "实际出口与变化", "pending", "尚未观测、结果过期，或隔离策略已变化。",
            "通过保护环境主动观测出口，建立本机变化记录。", "egress")
    if ready and fresh(streaming, now) and streaming.get("target") == STREAM_TARGET:
        state = "pass" if streaming.get("status") == "passed" else "warn"
        add("streaming", "20 秒流式通道样本", state,
            "本次持续收包样本通过。" if state == "pass" else "本次失败或未观察到持续收包时序，可能存在服务故障或缓冲。",
            "真实 Claude SSE / WebSocket 和长期会话仍需实测；未观察到复用不直接证明代理错误。", "streaming")
    else:
        add("streaming", "20 秒流式通道样本", "pending", "缺少当前策略下最近 10 分钟内的样本。",
            "需要时主动运行约 20 秒的流式通道测试。", "streaming")
    if fresh(audit, now) and audit.get("scope") == "current_process_environment_only":
        issues = any(item.get("level") == "attention" for item in audit.get("findings", []) if isinstance(item, dict))
        add("environment", "宿主进程配置", "warn" if issues else "pass",
            "发现代理或 API / TLS 环境设置需要核对。" if issues else "本次白名单环境检查未发现上述配置问题。",
            "在诊断页查看具体提示；面板环境不等于运行中的 Claude 环境，客户端和项目设置尚未读取。", "audit-details")
    else:
        add("environment", "宿主进程配置", "pending", "尚未执行最近 10 分钟内的离线检查。",
            "离线检查代理变量冲突、NO_PROXY、API 端点覆盖和证书验证设置。", "audit")
    add("browser", "浏览器 DNS / WebRTC / 环境", "pending", "面板尚未自动取得浏览器实测结果；Qt 面板不是受保护 Chrome。",
        "打开受保护的 Net.Coffee 页面，分别查看 DNS、WebRTC、时区和语言；第三方分数不作为官方判定。", "netcoffee")
    add("reputation", "IP 地区 / ASN / 信誉", "pending", "未接入经过验证的 IP 信誉数据源，也未核实使用资格。",
        "用第三方页面作参考，并查看官方支持地区；不因检测分数高而推断账号安全。", "netcoffee")
    if preview:
        rows = [replace(row, state="pending", evidence="界面演示：未连接 Ubuntu，尚未执行此项检查。") for row in rows]
    counts = {state: sum(row.state == state for row in rows) for state in LABELS}
    recommendations = [row for row in rows if row.state != "pass"]
    order = {"fix": 0, "warn": 1, "pending": 2}
    recommendations.sort(key=lambda row: order[row.state])
    return {"schema": 1, "checked_at": timestamp(), "counts": counts,
            "items": [asdict(row) for row in rows], "recommendations": [asdict(row) for row in recommendations],
            "account_safety": "not_assessed", "note": "本机检查与设置建议，不是封号评分。未检测和过期结果不会显示为通过。"}
