"""Optional, unprivileged PySide6 desktop panel. No Qt in privileged services."""
import argparse
from datetime import datetime
import json
import math
import os
from pathlib import Path
import pwd
import queue
import subprocess
import sys
import threading
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QProcess, QTimer, QUrl
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon, QPainter, QPen, QPixmap, QTextCursor
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QFrame,
                               QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                               QMessageBox, QPushButton, QScrollArea, QSizePolicy,
                               QStackedWidget, QTextEdit, QVBoxLayout, QWidget, QTableWidget,
                               QTableWidgetItem, QHeaderView, QAbstractItemView, QProgressBar)

from . import __version__
from .config import CONFIG, load_config
from .gui_model import (CLI, dashboard, desktop_quote, extension_versions, install_command,
                        launch_command, missing_dependencies, terminal_command)
from .diagnostics import EGRESS_TARGET, STREAM_TARGET, History, audit_environment, diagnostic_report, mask_ip, save_report, timestamp
from .inspection import LABELS, checklist
from .external_audit import ITEMS as UPSTREAM_ITEMS, SCOPE as UPSTREAM_SCOPE, policy_context, shared_egress, summary as upstream_summary, report as upstream_report

CREAM, INK, MUTED, CLAY = "#F6F3ED", "#302E2B", "#807A71", "#C66F4D"
COLORS = {"neutral": "#807A71", "good": "#3E7965", "warn": "#A77532", "bad": "#B65149"}
PANEL_ICON = Path(__file__).parent / "assets" / "claude-protect.png"

STYLE = """
QWidget { color: #302E2B; font-size: 13px; }
QMainWindow, QWidget#canvas { background: #F6F3ED; }
QFrame#sidebar { background: #2C2C29; border: none; }
QLabel#brand { color: #F5F0E7; font-size: 20px; font-weight: 600; }
QLabel#sideMuted { color: #A8A59B; font-size: 12px; }
QPushButton#nav { text-align: left; padding: 13px 16px; color: #B9B6AC;
 background: transparent; border: none; border-radius: 9px; font-size: 14px; }
QPushButton#nav:hover { background: #383834; color: #F5F0E7; }
QPushButton#nav:checked { background: #494039; color: #F4CCB6; }
QLabel#eyebrow { color: #93877B; font-size: 11px; font-weight: 600; }
QLabel#pageTitle { font-size: 25px; font-weight: 600; }
QLabel#muted { color: #807A71; }
QLabel#small { color: #807A71; font-size: 11px; }
QLabel#heading { font-size: 17px; font-weight: 600; }
QLabel#heroTitle { font-size: 30px; font-weight: 600; color: #45382F; }
QFrame#hero { background: #EFE5D8; border: 1px solid #E5D9CA; border-radius: 18px; }
QFrame#card { background: #FFFEFA; border: 1px solid #E6E0D6; border-radius: 12px; }
QLabel#tileValue { font-size: 20px; font-weight: 600; }
QLabel#pill { background: #E9E7DC; color: #68685B; padding: 5px 10px; border-radius: 9px; font-size: 11px; }
QLabel#notice { color: #956A3A; background: #F2E8D7; padding: 10px 14px; border-radius: 8px; }
QPushButton { background: #FFFEFA; border: 1px solid #DDD5C9; border-radius: 8px;
 padding: 10px 16px; font-size: 13px; }
QPushButton:hover { background: #F1EBE2; border-color: #BDAE9F; }
QPushButton:pressed { background: #E9E0D5; }
QPushButton:disabled { color: #A9A299; background: #EFECE5; border-color: #E5E0D8; }
QPushButton#primary { background: #C66F4D; color: #FFFFFF; border-color: #C66F4D; font-weight: 600; }
QPushButton#primary:hover { background: #B76242; border-color: #B76242; }
QPushButton#primary:disabled { color: #E8D4C9; background: #C5AB9E; border-color: #C5AB9E; }
QPushButton#danger { color: #A34840; }
QPushButton#danger:disabled { color: #A9A299; }
QLineEdit, QComboBox { background: #FFFFFF; border: 1px solid #DED7CC; border-radius: 7px;
 padding: 9px 11px; min-height: 20px; selection-background-color: #D08C6E; }
QLineEdit:focus, QComboBox:focus { border-color: #C66F4D; }
QLineEdit:read-only { color: #81796D; background: #F4F0E9; }
QComboBox::drop-down { border: none; width: 25px; }
QComboBox QAbstractItemView { background: #FFFFFF; color: #302E2B; selection-background-color: #EFE5D8; }
QCheckBox { spacing: 9px; }
QTextEdit { background: #F9F7F2; border: 1px solid #E4DED3; border-radius: 8px;
 padding: 10px; font-size: 12px; selection-background-color: #E6C5B2; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #D7CFC3; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QTableWidget { background: #FFFEFA; border: 1px solid #E4DED3; border-radius: 6px; }
QHeaderView::section { background: #EEE8DF; color: #756A5E; border: none; padding: 7px; }
QTableWidget::item { padding: 5px; }
QProgressBar { border: none; background: #E9E2D6; border-radius: 4px; max-height: 8px; }
QProgressBar::chunk { background: #C66F4D; border-radius: 4px; }
QToolTip { background: #302E2B; color: #FFFFFF; padding: 7px; border: none; }
"""


def label(text, name="", wrap=False):
    item = QLabel(text)
    item.setObjectName(name)
    item.setWordWrap(wrap)
    item.setTextFormat(Qt.TextFormat.PlainText)
    return item


def button(text, callback, primary=False):
    item = QPushButton(text)
    if primary:
        item.setObjectName("primary")
    item.setCursor(Qt.CursorShape.PointingHandCursor)
    item.clicked.connect(callback)
    return item


def card():
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 19, 22, 19)
    layout.setSpacing(12)
    return frame, layout


class Clawd(QWidget):
    """Claude Code's Clawd silhouette, locally painted with crisp pixel blocks.

    Character: Anthropic. Panel animation code: this project. See NOTICE.md.
    """
    ART = (" ▐▛███▜▌ ", "▝▜█████▛▘", "  ▘▘ ▝▝  ")
    QUADRANTS = {" ": (0, 0, 0, 0), "▐": (0, 1, 0, 1), "▛": (1, 1, 1, 0),
                 "█": (1, 1, 1, 1), "▜": (1, 1, 0, 1), "▌": (1, 0, 1, 0),
                 "▝": (0, 1, 0, 0), "▘": (1, 0, 0, 0)}

    def __init__(self, parent=None, compact=False):
        super().__init__(parent)
        self.compact = compact
        self.mood = "idle"
        self.setFixedSize(42, 42) if compact else self.setFixedSize(216, 192)
        self.clock = QTimer(self)
        self.clock.timeout.connect(self.update)
        if not compact:
            self.clock.start(80)
        self.setToolTip("Clawd · Claude Code 像素伙伴")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.scale(self.width() / 216, self.height() / 192)
        phase = time.monotonic()
        if not self.compact:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#DFD1BE"))
            painter.drawEllipse(QRectF(40, 155, 136, 10))
            painter.setPen(QPen(QColor("#BCAF9B"), 2))
            for x, y in ((22, 42), (193, 35), (190, 140)):
                painter.drawLine(QPointF(x - 4, y), QPointF(x + 4, y))
                painter.drawLine(QPointF(x, y - 4), QPointF(x, y + 4))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        offset = 0 if self.compact else round(math.sin(phase * (4 if self.mood == "busy" else 1.8)) * 2)
        painter.translate(27, 55 + offset)
        for row_index, row in enumerate(self.ART):
            for column, char in enumerate(row):
                for quadrant, occupied in enumerate(self.QUADRANTS[char]):
                    if occupied:
                        x, y = column * 2 + quadrant % 2, row_index * 2 + quadrant // 2
                        painter.fillRect(QRectF(x * 9, y * 17, 9, 17), QColor("#D77757"))
        # The two notches in the classic terminal silhouette are the dark eyes.
        blink = not self.compact and phase % 5.1 < 0.18
        for x in (5, 12):
            painter.fillRect(QRectF(x * 9, 17, 9, 17), QColor("#D77757" if blink else "#302E2B"))
            if blink:
                painter.fillRect(QRectF(x * 9, 28, 9, 4), QColor("#302E2B"))
        painter.resetTransform()
        if not self.compact and self.mood in ("ready", "alert", "busy"):
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            color = {"ready": "#3E7965", "alert": "#B65149", "busy": "#A77532"}[self.mood]
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(color))
            painter.drawEllipse(QRectF(169, 115, 27, 27))
            painter.setPen(QPen(QColor("#FFFEFA"), 2.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            if self.mood == "ready":
                painter.drawLine(QPointF(177, 128), QPointF(181, 132))
                painter.drawLine(QPointF(181, 132), QPointF(188, 124))
            elif self.mood == "alert":
                painter.drawLine(QPointF(182, 122), QPointF(182, 129))
                painter.drawPoint(QPointF(182, 135))
            else:
                painter.drawArc(QRectF(176, 122, 13, 13), int(phase * 180) % 360 * 16, 240 * 16)
        painter.end()

    def set_mood(self, mood):
        self.mood = mood
        self.update()


class Panel(QMainWindow):
    def __init__(self, *, demo=False):
        super().__init__()
        self.demo = demo
        self.status_data = None
        self.status_checked_at = None
        self.status_error = ""
        self.installed_config = None
        self.configuration_error = ""
        self.dependency_missing = None
        self.plugin_versions = {}
        self.plugin_error = ""
        self.keyring_data = None
        self.probe_data = None
        self.audit_data = None
        self.egress_data = None
        self.egress_history = []
        self.egress_change = None
        self.streaming_data = None
        self.upstream_data = None
        self.history = History()
        self.processes = {}
        self.background = set()
        self.events = queue.SimpleQueue()
        self.state_signature = None
        self.live_buttons = []
        self.nav_buttons = []
        self._closing = False
        self.inspection_running = False
        self.inspection_cancelled = False
        self.inspection_steps = []
        self.inspection_completed = 0
        self.restoration_note = "还原会移除本项目系统组件；以后需要重新安装才能使用受保护入口。"
        self.setWindowTitle("Claude Protect · 控制面板" + (" · 界面演示" if demo else ""))
        self.resize(1220, 880)
        self.setMinimumSize(1050, 640)
        self.setStyleSheet(STYLE)
        self._build()
        self.event_timer = QTimer(self)
        self.event_timer.timeout.connect(self._drain_events)
        self.event_timer.start(150)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        if not demo:
            self.refresh_timer.start(15000)
        self.refresh()

    def _build(self):
        canvas = QWidget()
        canvas.setObjectName("canvas")
        self.setCentralWidget(canvas)
        outer = QHBoxLayout(canvas)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        side = QFrame()
        side.setObjectName("sidebar")
        side.setFixedWidth(216)
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(20, 28, 20, 24)
        logo = QHBoxLayout()
        logo.addWidget(Clawd(compact=True))
        logo.addWidget(label("Claude\nProtect", "brand"))
        side_layout.addLayout(logo)
        side_layout.addSpacing(31)
        side_layout.addWidget(label("你的工作小站", "sideMuted"))
        side_layout.addSpacing(9)
        for index, name in enumerate(("工作台", "连接配置", "诊断与日志", "环境检测", "使用指南")):
            item = button(f"{index + 1:02d}     {name}", lambda checked=False, i=index: self.navigate(i))
            item.setObjectName("nav")
            item.setCheckable(True)
            self.nav_buttons.append(item)
            side_layout.addWidget(item)
        side_layout.addStretch()
        side_layout.addWidget(label("少一点配置负担\n多一点专注时间", "sideMuted", True))
        side_layout.addSpacing(18)
        side_layout.addWidget(label(f"v{__version__}  ·  PySide6\nUbuntu 桌面 / 本地使用", "sideMuted"))
        outer.addWidget(side)
        main = QVBoxLayout()
        main.setContentsMargins(30, 24, 30, 17)
        main.setSpacing(14)
        top = QHBoxLayout()
        self.page_title = label("工作台", "pageTitle")
        top.addWidget(self.page_title)
        top.addStretch()
        top.addWidget(label("界面演示 · 未连接系统" if self.demo else "UBUNTU DESKTOP", "pill"))
        self.refresh_button = button("刷新状态", self.refresh)
        top.addWidget(self.refresh_button)
        main.addLayout(top)
        if self.demo:
            main.addWidget(label("当前只预览界面，所有系统操作均已禁用；显示内容不代表实际检查结果。", "notice", True))
        self.pages = QStackedWidget()
        main.addWidget(self.pages, 1)
        for create in (self._overview, self._configuration, self._diagnostics, self._inspection, self._guide):
            content = QWidget()
            content.setObjectName("canvas")
            layout = QVBoxLayout(content)
            layout.setContentsMargins(0, 0, 8, 0)
            layout.setSpacing(16)
            create(layout)
            layout.addStretch()
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(content)
            self.pages.addWidget(scroll)
        self.footer = label("控制面板位于普通桌面；只有专用入口启动的应用进入隔离。", "small", True)
        main.addWidget(self.footer)
        outer.addLayout(main, 1)
        self.navigate(0)

    def _live(self, text, callback, primary=False):
        item = button(text, callback, primary)
        self.live_buttons.append(item)
        if self.demo:
            item.setEnabled(False)
        return item

    def _overview(self, layout):
        hero = QFrame()
        hero.setObjectName("hero")
        row = QHBoxLayout(hero)
        row.setContentsMargins(27, 18, 20, 18)
        words = QVBoxLayout()
        words.setSpacing(12)
        words.addWidget(label("CLAUDE PROTECT  /  专注每一次连接", "eyebrow"))
        self.hero_title = label("给工作环境一道边界", "heroTitle", True)
        words.addWidget(self.hero_title)
        self.hero_detail = label("先连接代理，再打开你的专用工作窗口。", "muted", True)
        words.addWidget(self.hero_detail)
        words.addWidget(label("网络路径可检查 · 代理断线不回退直连", "small"))
        row.addLayout(words, 1)
        self.robot = Clawd()
        row.addWidget(self.robot)
        layout.addWidget(hero)
        tiles = QHBoxLayout()
        tiles.setSpacing(12)
        self.tiles = []
        for _ in range(4):
            tile, content = card()
            content.setContentsMargins(16, 17, 16, 17)
            title = label("", "muted")
            value = label("", "tileValue")
            detail = label("", "small", True)
            detail.setMinimumHeight(34)
            content.addWidget(title)
            content.addWidget(value)
            content.addWidget(detail)
            tiles.addWidget(tile, 1)
            self.tiles.append((title, value, detail))
        layout.addLayout(tiles)
        work, content = card()
        title_row = QHBoxLayout()
        title_row.addWidget(label("开始工作", "heading"))
        title_row.addStretch()
        title_row.addWidget(label("专用配置目录，登录状态可保留", "small"))
        content.addLayout(title_row)
        row = QHBoxLayout()
        self.folder = QLineEdit()
        self.folder.setPlaceholderText("选择项目文件夹；留空则打开空白工作窗口")
        row.addWidget(self.folder, 1)
        row.addWidget(button("选择文件夹", self.choose_folder))
        content.addLayout(row)
        actions = QHBoxLayout()
        self.code_button = self._live("打开 VS Code   ↗", self.open_code, True)
        self.browser_button = self._live("打开 Claude 网页   ↗", lambda: self.launch("browser", [CLI, "browser", "https://claude.ai/"]))
        actions.addWidget(self.code_button, 1)
        actions.addWidget(self.browser_button, 1)
        content.addLayout(actions)
        layout.addWidget(work)
        row = QHBoxLayout()
        row.addWidget(button("配置代理与安装", lambda: self.navigate(1)))
        row.addWidget(self._live("检查密钥链", self.check_keyring))
        row.addWidget(self._live("运行联网验证", self.run_probe))
        self.upstream_overview_button = self._live("检测外部代理", self.open_upstream_check)
        row.addWidget(self.upstream_overview_button)
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(label("它帮助你约束连接路径，不承诺账号不会被封。Ubuntu 内核、授权与浏览器实际存储仍需实机验收。", "small", True))
        self.inspection_hint = label("", "notice", True)
        layout.addWidget(self.inspection_hint)
        layout.addWidget(button("查看环境检测与设置建议", lambda: self.navigate(3)))

    def _configuration(self, layout):
        self.installation_summary = label("正在读取本机安装状态…", "notice", True)
        layout.addWidget(self.installation_summary)
        source, form = card()
        heading = QHBoxLayout()
        heading.addWidget(label("01  准备安装环境", "heading"))
        heading.addStretch()
        self.restore_top_button = self._live("还原系统配置…", self.uninstall_core)
        self.restore_top_button.setObjectName("danger")
        heading.addWidget(self.restore_top_button)
        form.addLayout(heading)
        form.addWidget(label("安装会打开系统终端。管理员密码和代理密码只在该终端输入，面板不收集账号凭据。", "muted", True))
        row = QHBoxLayout()
        root = Path(__file__).resolve().parents[2]
        self.release = QLineEdit(str(root) if (root / "scripts/install.py").is_file() else "")
        self.release.setPlaceholderText("完整发行包解压后的文件夹")
        row.addWidget(self.release, 1)
        row.addWidget(button("选择安装包目录", self.choose_release))
        form.addLayout(row)
        self.user = QLineEdit(pwd.getpwuid(os.getuid()).pw_name)
        self.user.setReadOnly(True)
        form.addWidget(label("当前桌面用户", "small"))
        form.addWidget(self.user)
        self.dependencies_button = self._live("检查 / 安装系统依赖…", self.install_dependencies)
        form.addWidget(self.dependencies_button)
        self.dependencies_note = label("", "small", True)
        form.addWidget(self.dependencies_note)
        layout.addWidget(source)
        connection, form = card()
        form.addWidget(label("02  选择连接方式", "heading"))
        self.mode = QComboBox()
        self.mode.addItem("受控模式 · 远端 HTTPS CONNECT 代理", "managed")
        self.mode.addItem("兼容模式 · 已有 Clash / Mihomo / sing-box", "external")
        form.addWidget(self.mode)
        self.mode_forms = QStackedWidget()
        managed = QWidget()
        grid = QGridLayout(managed)
        grid.setContentsMargins(0, 5, 0, 0)
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("服务商提供的公网 IPv4")
        self.port = QLineEdit("443")
        self.port.setMaximumWidth(130)
        self.tls_name = QLineEdit()
        self.tls_name.setPlaceholderText("代理服务器的 TLS 证书域名")
        grid.addWidget(label("远端代理 IPv4", "small"), 0, 0)
        grid.addWidget(label("端口", "small"), 0, 1)
        grid.addWidget(self.ip, 1, 0)
        grid.addWidget(self.port, 1, 1)
        grid.addWidget(label("证书域名（SNI）", "small"), 2, 0)
        grid.addWidget(self.tls_name, 3, 0, 1, 2)
        self.auth = QCheckBox("代理需要用户名与密码（在系统终端中输入）")
        grid.addWidget(self.auth, 4, 0, 1, 2)
        grid.addWidget(label("仅支持经 TLS 验证的 HTTP/1.x CONNECT；机场订阅、SOCKS 节点和 Claude API Key 不能直接填写。", "small", True), 5, 0, 1, 2)
        self.mode_forms.addWidget(managed)
        external = QWidget()
        external_layout = QVBoxLayout(external)
        external_layout.setContentsMargins(0, 5, 0, 0)
        external_layout.addWidget(label("本机 127.0.0.1 的 HTTP / 混合代理端口", "small"))
        self.local_port = QLineEdit("20808")
        external_layout.addWidget(self.local_port)
        external_layout.addWidget(label("先启动你已有的代理软件，并填写实际端口。这种模式仅约束应用侧连接；代理自身 DNS、DIRECT 与上游出口仍由该软件配置。", "notice", True))
        self.mode_forms.addWidget(external)
        self.mode.currentIndexChanged.connect(self.mode_forms.setCurrentIndex)
        form.addWidget(self.mode_forms)
        self.install_button = self._live("在终端中安装系统组件…", self.install_core, True)
        form.addWidget(self.install_button)
        self.install_note = label("", "small", True)
        form.addWidget(self.install_note)
        layout.addWidget(connection)
        plugins, form = card()
        form.addWidget(label("03  安装工作窗口的插件", "heading"))
        form.addWidget(label("系统组件就绪后，分别安装状态插件和官方 Claude Code 插件；然后返回工作台打开窗口。", "muted", True))
        self.protect_plugin_status = label("", "small", True)
        self.official_plugin_status = label("", "small", True)
        form.addWidget(self.protect_plugin_status)
        form.addWidget(self.official_plugin_status)
        row = QHBoxLayout()
        self.protect_plugin_button = self._live("安装 Protect 状态插件", lambda: self.launch("plugin", [CLI, "install-plugin"]))
        self.official_plugin_button = self._live("安装 Claude Code 扩展", lambda: self.launch("official", [CLI, "install-official"]))
        row.addWidget(self.protect_plugin_button)
        row.addWidget(self.official_plugin_button)
        form.addLayout(row)
        layout.addWidget(plugins)
        recovery, content = card()
        content.addWidget(label("04  还原系统配置", "heading"))
        content.addWidget(label("普通应用仍使用原来的主机网络；专用窗口的速度取决于代理与共享资源。需要撤销本项目的系统配置时，可在此还原。", "muted", True))
        content.addWidget(label("移除：专用网络隔离、服务、防火墙规则、sudo 授权和受控代理凭据。\n保留：项目、Claude 登录资料、专用窗口数据、外部代理软件及其配置。", "muted", True))
        self.restore_button = self._live("还原系统配置…", self.uninstall_core)
        self.restore_button.setObjectName("danger")
        content.addWidget(self.restore_button)
        self.restore_status = label(self.restoration_note, "small", True)
        content.addWidget(self.restore_status)
        layout.addWidget(recovery)

    def _diagnostics(self, layout):
        upstream_card, content = card()
        row = QHBoxLayout()
        row.addWidget(label("外部代理检测", "heading"))
        row.addStretch()
        self.upstream_button = self._live("检测外部代理", self.run_upstream_check, True)
        row.addWidget(self.upstream_button)
        self.dns_runtime_button = self._live("授权读取 DNS 运行配置…", self.read_dns_runtime)
        row.addWidget(self.dns_runtime_button)
        content.addLayout(row)
        content.addWidget(label("自动识别 Clash Verge / Mihomo，核对 Claude 测试连接、DNS 配置和隔离内出口。仅在点击时联网，不登录 Claude，不更改代理或 TUN。其他代理可检查 TLS 和出口，无法识别的项目保留为尚未验证。", "muted", True))
        self.upstream_summary = label("尚未检测。", "notice", True)
        content.addWidget(self.upstream_summary)
        self.upstream_table = QTableWidget(0, 3)
        self.upstream_table.setHorizontalHeaderLabels(["检测项目", "结果", "依据 / 下一步"])
        self.upstream_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.upstream_table.setColumnWidth(0, 145)
        self.upstream_table.setColumnWidth(1, 95)
        self.upstream_table.verticalHeader().hide()
        self.upstream_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.upstream_table.setWordWrap(True)
        self.upstream_table.setMinimumHeight(250)
        content.addWidget(self.upstream_table)
        content.addWidget(label("结果是本次快照，10 分钟后过期；切换节点后请重新检测。软件会自动检查回退配置，不中断当前上游做故障注入。DNS 运行配置在管理员目录中，授权后由软件自动读取，无需手工翻配置。", "small", True))
        layout.addWidget(upstream_card)
        core, content = card()
        content.addWidget(label("核心保护与验收进度", "heading"))
        self.core_summary = label("", "muted", True)
        content.addWidget(self.core_summary)
        content.addWidget(self._live("验证流式通道（约 20 秒）", self.check_stream, True))
        self.stream_summary = label("主动访问 httpbin 的滴流端点，观察持续收包与连接复用。不使用 Claude 账号，不代表真实 Claude SSE / WebSocket 已验收。", "small", True)
        content.addWidget(self.stream_summary)
        layout.addWidget(core)
        exit_card, content = card()
        content.addWidget(label("实际出口观测", "heading"))
        content.addWidget(label("点击后，从受保护环境向 ipify 发出两次 HTTPS 请求。固定代理入口不保证远端出口固定；观测结果不代表 Anthropic 看到的出口。", "muted", True))
        row = QHBoxLayout()
        row.addWidget(self._live("观测出口（联网）", self.observe_egress, True))
        row.addWidget(self._live("清除本机历史", self.clear_history))
        self.hide_ip = QCheckBox("隐藏 IP 尾段")
        self.hide_ip.setChecked(True)
        self.hide_ip.toggled.connect(self.render_egress)
        row.addStretch()
        row.addWidget(self.hide_ip)
        content.addLayout(row)
        self.egress_summary = label("尚未观测 · 不会在后台自动联网检测", "muted", True)
        content.addWidget(self.egress_summary)
        self.history_table = QTableWidget(0, 3)
        self.history_table.setHorizontalHeaderLabels(["观测时间（UTC）", "检测服务看到的出口", "两次采样"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.verticalHeader().hide()
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setShowGrid(False)
        self.history_table.setMinimumHeight(110)
        self.history_table.setMaximumHeight(180)
        content.addWidget(self.history_table)
        content.addWidget(label("本机最多保留 30 次完整观测，文件仅当前用户可读写；历史保存完整 IP，导出报告默认隐藏尾段。", "small", True))
        layout.addWidget(exit_card)
        environment_card, content = card()
        row = QHBoxLayout()
        row.addWidget(label("配置与环境自检", "heading"))
        row.addStretch()
        row.addWidget(self._live("检查当前环境（离线）", self.run_audit))
        content.addLayout(row)
        self.audit_summary = label("检查代理变量冲突、NO_PROXY 旁路、API 端点覆盖与证书验证设置。只检查面板自身环境，不读取账号凭据或客户端设置文件。", "muted", True)
        content.addWidget(self.audit_summary)
        layout.addWidget(environment_card)
        checks, content = card()
        content.addWidget(label("检查与诊断", "heading"))
        content.addWidget(label("刷新只读取状态。联网验证由你主动发起，会通过隔离环境连接 example.com，不登录 Claude。", "muted", True))
        row = QHBoxLayout()
        row.addWidget(button("刷新隔离状态", self.refresh))
        row.addWidget(self._live("检查密钥链通道", self.check_keyring))
        row.addWidget(self._live("运行联网验证", self.run_probe, True))
        row.addWidget(button("导出脱敏报告…", self.export_report))
        row.addStretch()
        content.addLayout(row)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(170)
        self.details.setMaximumHeight(260)
        content.addWidget(self.details)
        layout.addWidget(checks)
        contrast, content = card()
        content.addWidget(label("受保护浏览器交叉验证", "heading"))
        content.addWidget(label("第三方页面会收到访问 IP。其评分不是官方风控结果，也不会被面板当作检查通过的依据；WebRTC 与权威 DNS 结果仍需你在页面中查看。", "muted", True))
        row = QHBoxLayout()
        row.addWidget(self._live("IP / DNS / WebRTC 对照", lambda: self.launch("browser-coffee", [CLI, "browser", "https://ip.net.coffee/claude/"])))
        row.addWidget(self._live("浏览器环境对照", lambda: self.launch("browser-scanner", [CLI, "browser", "https://fuck-claude.app/"])))
        row.addStretch()
        content.addLayout(row)
        layout.addWidget(contrast)
        logs, content = card()
        row = QHBoxLayout()
        row.addWidget(label("本次会话日志", "heading"))
        row.addStretch()
        row.addWidget(button("复制日志", self.copy_log))
        row.addWidget(button("清空", lambda: self.log.clear()))
        content.addLayout(row)
        content.addWidget(label("日志仅保存在面板内存中；系统终端输入的密码不会进入这里。", "small", True))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(210)
        self.log.document().setMaximumBlockCount(1200)
        content.addWidget(self.log)
        layout.addWidget(logs)

    def _inspection(self, layout):
        header, content = card()
        row = QHBoxLayout()
        row.addWidget(Clawd(compact=True))
        row.addWidget(label("配好以后，再验一次", "heading"))
        row.addStretch()
        content.addLayout(row)
        content.addWidget(label("自动检测隔离、代理、DNS、IPv6、密钥链、出口与流式通道。联网使用 example.com、ipify、httpbin，并测试 claude.ai 的匿名 TLS/DNS；不登录 Claude。", "muted", True))
        row = QHBoxLayout()
        self.inspection_start = self._live("开始检测（含联网）", self.start_inspection, True)
        row.addWidget(self.inspection_start)
        self.inspection_stop = self._live("停止后续步骤", self.cancel_inspection)
        self.inspection_stop.setEnabled(False)
        row.addWidget(self.inspection_stop)
        row.addStretch()
        self.include_stream = QCheckBox("包含约 20 秒流式样本")
        self.include_stream.setChecked(True)
        row.addWidget(self.include_stream)
        content.addLayout(row)
        self.inspection_progress = QProgressBar()
        self.inspection_progress.setRange(0, 5)
        self.inspection_progress.setValue(0)
        self.inspection_progress.setTextVisible(False)
        content.addWidget(self.inspection_progress)
        self.inspection_run_note = label("尚未开始。不会自动修改代理、系统语言或时区。", "small", True)
        content.addWidget(self.inspection_run_note)
        self.inspection_summary = label("", "heading", True)
        content.addWidget(self.inspection_summary)
        layout.addWidget(header)
        results, content = card()
        content.addWidget(label("逐项结果与建议", "heading"))
        content.addWidget(label("绿色只代表有近期证据的本次检查。过期和未检测项目不会变绿；浏览器环境、IP 信誉与使用资格需要另外核对。", "small", True))
        self.inspection_table = QTableWidget(0, 3)
        self.inspection_table.setHorizontalHeaderLabels(["检测项目", "状态", "依据 / 下一步"])
        self.inspection_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.inspection_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.inspection_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.inspection_table.verticalHeader().hide()
        self.inspection_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inspection_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.inspection_table.setWordWrap(True)
        self.inspection_table.setShowGrid(False)
        self.inspection_table.setMinimumHeight(300)
        self.inspection_table.setMaximumHeight(460)
        content.addWidget(self.inspection_table)
        layout.addWidget(results)
        advice, content = card()
        content.addWidget(label("接下来怎么设置", "heading"))
        self.advice_layout = QVBoxLayout()
        self.advice_layout.setSpacing(14)
        content.addLayout(self.advice_layout)
        layout.addWidget(advice)
        row = QHBoxLayout()
        row.addWidget(self._live("打开 Net.Coffee 对照检测", self.open_netcoffee))
        row.addWidget(button("查看详细诊断", lambda: self.navigate(2)))
        row.addWidget(button("导出脱敏报告…", self.export_report))
        layout.addLayout(row)

    def _guide(self, layout):
        for title, text in (
            ("第一次使用", "① 安装官方 .deb 版 VS Code 和 Google Chrome。\n② 在「连接配置」选择代理方式，安装依赖与系统组件。\n③ 安装两个插件，回到工作台打开 VS Code。\n④ 在专用窗口内用自己的 Claude Pro / Max 账号完成登录。"),
            ("日常打开方式", "在工作台选择项目并打开 VS Code，或直接打开 Claude 网页。专用 Chrome 会保留自己的登录会话。普通 VS Code / Chrome 快捷方式打开的窗口不会自动进入隔离。"),
            ("Clawd 的状态", "等待：轻微浮动与眨眼。检查：显示旋转标记。就绪：显示绿色勾号。异常：显示红色提示。保留 Claude Code 的 Clawd 像素外形，状态以检查结果为准。"),
            ("密钥链与代理边界", "启动器要求默认桌面密钥链已解锁。通道预检不证明浏览器实际存储后端或磁盘加密已通过验收。受控模式约束专用代理服务的出口；兼容模式还需要检查外部代理的 DNS 与路由。"),
        ):
            frame, content = card()
            content.addWidget(label(title, "heading"))
            content.addWidget(label(text, "muted", True))
            layout.addWidget(frame)
        row = QHBoxLayout()
        row.addWidget(button("添加面板到应用菜单", self.add_shortcut))
        row.addWidget(button("打开完整说明", self.open_guide))
        row.addStretch()
        layout.addLayout(row)
        frame, content = card()
        content.addWidget(label("还原系统配置（移除配套组件）", "heading"))
        content.addWidget(label("先停止检测，关闭受保护 VS Code、浏览器及其后台进程，再在系统终端还原。用户数据与项目保留，专用代理凭据会删除。也可从「连接配置」进入。", "muted", True))
        uninstall = self._live("还原系统配置…", self.uninstall_core)
        uninstall.setObjectName("danger")
        content.addWidget(uninstall)
        layout.addWidget(frame)

    def navigate(self, index):
        self.pages.setCurrentIndex(index)
        self.page_title.setText(("工作台", "连接配置", "诊断与日志", "环境检测", "使用指南")[index])
        for i, item in enumerate(self.nav_buttons):
            item.setChecked(i == index)

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择项目文件夹", self.folder.text() or str(Path.home()))
        if folder:
            self.folder.setText(folder)

    def choose_release(self):
        folder = QFileDialog.getExistingDirectory(self, "选择发行包目录", self.release.text() or str(Path.home()))
        if folder:
            self.release.setText(folder)

    def report(self, text):
        cursor = self.log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(f"[{datetime.now():%H:%M:%S}] {text}\n")
        self.log.setTextCursor(cursor)

    def fail(self, error):
        self.report(str(error))
        QMessageBox.warning(self, "请检查一下", str(error))

    def refresh(self, *, after=None):
        if self._closing:
            return
        installed = CONFIG.exists() if not self.demo else False
        self.installed_config = None
        self.configuration_error = ""
        if not self.demo:
            self.dependency_missing = missing_dependencies()
            self.plugin_versions, self.plugin_error = extension_versions()
            if installed:
                try:
                    self.installed_config = load_config(CONFIG)
                except (OSError, ValueError, TypeError) as error:
                    self.configuration_error = "已有系统配置，但读取或校验失败：" + str(error)
        self.mode.setEnabled(not self.demo and not installed)
        for field in (self.local_port, self.ip, self.port, self.tls_name):
            field.setReadOnly(installed or self.demo)
        self.auth.setVisible(not installed)
        if self.installed_config is not None:
            config = self.installed_config
            self.mode.setCurrentIndex(self.mode.findData(config.proxy_mode))
            self.local_port.setText(str(config.upstream_port))
            self.ip.setText(config.upstream_ip or "")
            self.port.setText(str(config.upstream_remote_port))
            self.tls_name.setText(config.upstream_tls_name or "")
        self.install_button.setEnabled(not self.demo and not installed and "admin" not in self.background)
        self.restore_button.setEnabled(not self.demo and installed and "restore" not in self.background)
        self.restore_top_button.setEnabled(not self.demo and installed and "restore" not in self.background)
        self.restore_status.setText(self.restoration_note)
        self.install_note.setText("已显示实际安装配置。日常使用请返回工作台；更改代理配置需先关闭受保护应用并还原系统组件。" if installed else
                                  "系统组件只需安装一次；安装结果请在终端与工作台状态中确认。")
        if self.demo or not installed or not Path(CLI).is_file():
            self.status_data = None
            self.status_checked_at = None
            self.state_signature = None
            self.keyring_data = None
            self.probe_data = None
            self.egress_data = None
            self.egress_change = None
            self.streaming_data = None
            self.upstream_data = None
            self.status_error = "" if not installed else "已找到配置，但命令行组件缺失。"
            self.render()
            if callable(after):
                after()
            return
        self.robot.set_mood("busy")
        self.render_installation()
        self.command("status", [CLI, "status", "--json"], self._status_done, timeout=12000, after=after)

    def render_installation(self):
        installed = not self.demo and CONFIG.exists()
        ready = not self.demo and (self.status_data or {}).get("kernel_ok") is True
        if self.demo:
            summary = "界面演示 · 尚未读取实际安装状态"
            text = "在终端中安装系统组件…"
        elif not installed:
            summary = "系统组件尚未安装 · 请完成下方连接配置"
            text = "在终端中安装系统组件…"
        elif self.configuration_error:
            summary = self.configuration_error
            text = "已有配置 · 配置校验未通过"
        elif ready:
            summary = "系统组件已安装 · 隔离服务已核对，可以从工作台打开受保护应用"
            text = "系统组件已安装 · 隔离已核对"
        elif self.status_error:
            summary = "系统组件已有配置 · 状态核对未通过，请到诊断与日志查看原因"
            text = "已有配置 · 状态核对未通过"
        else:
            summary = "系统组件已有配置 · 正在核对隔离服务"
            text = "已有配置 · 正在核对"
        self.installation_summary.setText(summary)
        tone = "good" if ready and not self.configuration_error else "bad" if installed and (
            self.status_error or self.configuration_error) else "neutral"
        self.installation_summary.setStyleSheet(f"color: {COLORS[tone]};")
        self.install_button.setText(text)
        if self.demo:
            dependencies = "界面演示 · 未检查本机依赖"
        elif self.dependency_missing is None:
            dependencies = "尚未检查系统依赖"
        elif self.dependency_missing:
            dependencies = "缺少依赖：" + "、".join(self.dependency_missing)
        else:
            dependencies = "系统依赖已检测到；此按钮用于补装依赖，日常无需重复安装。"
        self.dependencies_note.setText(dependencies)
        self.dependencies_button.setText("检查 / 安装系统依赖…" if self.demo or self.dependency_missing is None or self.dependency_missing else
                                         "系统依赖已检测到（检查 / 补装…）")
        for identifier, name, note, action, key in (
            ("claude-protect-local.claude-protect", "Protect 状态插件", self.protect_plugin_status, self.protect_plugin_button, "plugin"),
            ("anthropic.claude-code", "Claude Code 扩展", self.official_plugin_status, self.official_plugin_button, "official"),
        ):
            version = self.plugin_versions.get(identifier)
            description = "演示模式 · 未核对" if self.demo else self.plugin_error or ("已安装 · v" + version if version else "未安装")
            note.setText(name + "：" + description)
            action.setText(("已安装 " if version and not self.demo else "安装 ") + name)
            action.setEnabled(ready and not version and not self.plugin_error and key not in self.background
                              and "restore" not in self.background)

    def render(self):
        self.render_installation()
        view = dashboard(self.status_data, installed=CONFIG.exists() if not self.demo else False,
                         error=self.status_error, keyring=self.keyring_data, probe=self.probe_data,
                         upstream=self.upstream_data)
        self.hero_title.setText("你的 Claude 工作小站" if self.demo else view["title"])
        self.hero_detail.setText("Clawd 已到位，等你在 Ubuntu 配好第一条连接。" if self.demo else view["detail"])
        self.robot.set_mood(view["mood"])
        for (title, value, detail), tile in zip(self.tiles, view["tiles"]):
            title.setText(tile.title)
            value.setText(tile.value)
            value.setStyleSheet(f"color: {COLORS[tile.tone]};")
            detail.setText(tile.detail)
        ready = bool(self.status_data and self.status_data.get("kernel_ok") is True) and not self.demo and "restore" not in self.background
        self.code_button.setEnabled(ready and "code" not in self.background)
        self.browser_button.setEnabled(ready and "browser" not in self.background)
        self.details.setPlainText(json.dumps({"隔离服务": self.status_data or self.status_error or "尚未安装 / 未连接",
                                             "上次密钥链预检": self.keyring_data or "尚未检查",
                                             "上次联网验证": self.probe_data or "尚未运行",
                                             "说明": "面板位于普通桌面，session_isolated=false 属于预期；专用窗口由启动器另行核对。"},
                                            ensure_ascii=False, indent=2))
        self.render_egress()
        self.render_upstream()
        self.render_core()
        self.render_inspection()

    def _status_done(self, code, text):
        self.status_checked_at = timestamp()
        previous = self.status_error
        try:
            result = json.loads(text)
            if not isinstance(result, dict) or "kernel_ok" not in result or (code and result.get("kernel_ok")):
                raise ValueError("状态响应格式无效")
            self.status_data = result
            self.status_error = "" if result.get("kernel_ok") else result.get("error", "内核策略核对未通过。")
        except (ValueError, TypeError):
            self.status_data = None
            self.status_error = text.strip() or "状态服务未响应。"
        signature = json.dumps(self.status_data, sort_keys=True)
        if signature != self.state_signature or self.status_error:
            self.probe_data = None
            self.keyring_data = None
            self.egress_data = None
            self.egress_change = None
            self.streaming_data = None
            self.upstream_data = None
        self.state_signature = signature
        if self.status_error and self.status_error != previous:
            self.report(self.status_error)
        self.render()
        self.footer.setText(f"状态读取于 {datetime.now():%H:%M:%S} · 面板位于普通桌面，仅专用入口启动的应用进入隔离。")

    def command(self, key, argv, callback, *, timeout=45000, after=None):
        if self.demo or self._closing:
            return
        if "restore" in self.background and key != "status":
            self.footer.setText("还原正在执行，请等待终端结束后再运行检查。")
            return
        if key in self.processes:
            if callable(after):
                self.processes[key]["waiters"].append(after)
            return
        process = QProcess(self)
        timer = QTimer(process)
        timer.setSingleShot(True)
        record = {"process": process, "timer": timer, "output": bytearray(), "error": "",
                  "waiters": [after] if callable(after) else []}
        self.processes[key] = record
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)

        def read():
            record["output"].extend(bytes(process.readAllStandardOutput()))
            if len(record["output"]) > 131072:
                record["output"] = record["output"][:131072]
                record["error"] = "命令输出过长，已停止读取。"
                process.kill()

        def finish(code):
            if self.processes.pop(key, None) is None:
                return
            timer.stop()
            read()
            text = record["error"] or record["output"].decode("utf-8", "replace")
            try:
                callback(code if not record["error"] else -1, text)
            finally:
                process.deleteLater()
                if not self._closing:
                    for waiter in record["waiters"]:
                        waiter()

        def expired():
            record["error"] = "检查超时；未将状态视为通过。"
            process.kill()

        process.readyReadStandardOutput.connect(read)
        process.finished.connect(lambda code, status: finish(code))
        process.errorOccurred.connect(lambda error: finish(-1) if error == QProcess.ProcessError.FailedToStart else None)
        timer.timeout.connect(expired)
        process.start(argv[0], argv[1:])
        timer.start(timeout)

    def check_keyring(self, *, after=None):
        if self.demo:
            return
        if not Path(CLI).is_file():
            self.fail("请先在连接配置中安装系统组件。")
            return
        self.robot.set_mood("busy")
        self.report("正在启动过滤通道并检查默认密钥链；不会读取密码或 Cookie。")

        def done(code, text):
            try:
                result = json.loads(text)
                self.keyring_data = result if not code and isinstance(result, dict) else None
            except ValueError:
                self.keyring_data = None
            if not self.keyring_data:
                self.keyring_data = {"available": False, "state": "failed"}
            self.keyring_data["checked_at"] = timestamp()
            self.report(text or "密钥链检查未完成。")
            self.render()
        self.command("keyring", [CLI, "keyring-status", "--json", "--start"], done, after=after)

    def run_probe(self, *, after=None):
        if self.demo:
            return
        if not Path(CLI).is_file():
            self.fail("请先在连接配置中安装系统组件。")
            return
        self.robot.set_mood("busy")
        self.report("正在隔离环境中验证直连阻断，并经代理连接 example.com:443。")
        self.probe_data = None
        started_policy = self.state_signature

        def done(code, text):
            if self.state_signature != started_policy:
                self.probe_data = None
                self.report("验证期间隔离状态变化，已丢弃本次联网结果。")
                self.render()
                return
            try:
                result = json.loads(text)
                self.probe_data = result if isinstance(result, dict) else {"passed": False}
                if code:
                    self.probe_data["passed"] = False
            except ValueError:
                self.probe_data = {"passed": False, "error": text}
            self.probe_data["checked_at"] = timestamp()
            self.report(text or "联网验证未完成。")
            self.render()
        self.command("probe", [CLI, "probe"], done, timeout=65000, after=after)

    def open_upstream_check(self):
        self.navigate(2)
        self.run_upstream_check()

    def run_upstream_check(self, *, after=None):
        if self.demo or self._closing:
            return
        if "upstream" in self.processes:
            if callable(after):
                self.processes["upstream"]["waiters"].append(after)
            return
        if (not self.installed_config or self.installed_config.proxy_mode != "external"
                or not (self.status_data or {}).get("kernel_ok")):
            self.upstream_data = None
            self.render_upstream()
            if callable(after):
                QTimer.singleShot(0, after)
            return
        self.upstream_data = None
        started_policy = self.state_signature
        context = policy_context(self.installed_config)
        self.egress_data = None
        self.egress_change = None
        self.run_audit()
        self.report("开始外部代理检测：读取本机代理接口和 DNS 配置，经代理测试 claude.ai TLS，并在隔离内观测 ipify 出口；不使用账号登录信息。")

        def done(code, text):
            self.upstream_data = None
            self.egress_data = None
            self.egress_change = None
            try:
                result = json.loads(text)
                if (code or self.state_signature != started_policy or not isinstance(result, dict)
                        or result.get("schema") != 1 or result.get("scope") != UPSTREAM_SCOPE
                        or result.get("policy_context") != context or result.get("status") != "complete"
                        or not isinstance(result.get("items"), list)
                        or {item.get("id") for item in result["items"]} != set(UPSTREAM_ITEMS)
                        or any(item.get("state") not in LABELS or not isinstance(item.get("detail"), str)
                               for item in result["items"])):
                    raise ValueError()
                self.upstream_data = result
                self.egress_data = shared_egress(result)
                if self.egress_data:
                    try:
                        saved = self.history.record(self.egress_data)
                        self.egress_history = saved["records"]
                        self.egress_change = saved["changed_since_previous"]
                        self.egress_data["changed_since_previous"] = self.egress_change
                    except (OSError, ValueError):
                        self.report("本次出口检测结果已同步；历史记录保存失败，请检查本机历史文件权限。")
            except (ValueError, TypeError, AttributeError):
                self.upstream_data = {"status": "failed", "checked_at": timestamp(), "items": []}
            self.report("外部代理检测结束：" + upstream_summary(self.upstream_data)[0] + "。详情见诊断页。")
            self.render()
        # Run the same module as this GUI; source GUI upgrades need no privileged reinstall.
        self.command("upstream", [sys.executable, str(Path(__file__).with_name("external_audit.py"))], done,
                     timeout=85000, after=after)
        self.render_upstream()

    def render_upstream(self):
        running = "upstream" in self.processes
        enabled = (not self.demo and not running and "restore" not in self.background
                   and (self.status_data or {}).get("kernel_ok") is True
                   and self.installed_config is not None and self.installed_config.proxy_mode == "external")
        for control in (self.upstream_button, self.upstream_overview_button):
            control.setEnabled(enabled)
            control.setText("正在检测外部代理…" if running else "检测外部代理")
        self.dns_runtime_button.setEnabled(enabled and "dns-admin" not in self.background and not self.inspection_running)
        title, detail = upstream_summary(self.upstream_data)
        stamp = (self.upstream_data or {}).get("checked_at", "")
        note = "正在读取代理状态并进行有时限的联网检查，面板可继续操作…" if running else title + "。" + detail
        if self.installed_config and self.installed_config.proxy_mode != "external":
            note = "当前使用受控上游；此检测入口用于已有 Clash/Mihomo 等外部代理。"
        if stamp:
            note += "\n检测时间（UTC）：" + stamp
        self.upstream_summary.setText(note)
        from .inspection import fresh
        current = fresh(self.upstream_data or {})
        rows = (self.upstream_data or {}).get("items", [])
        self.upstream_table.setRowCount(len(rows))
        colors = {"pass": "good", "warn": "warn", "fix": "bad", "pending": "neutral"}
        labels = {"pass": "已通过", "warn": "检测有提示", "fix": "发现问题", "pending": "未能验证"}
        for row, item in enumerate(rows):
            state = item["state"] if current else "pending"
            evidence = item["detail"] if current else "结果已过期，请重新检测。"
            if item["id"] == "egress" and current:
                ips = (self.upstream_data or {}).get("egress", {}).get("ips", [])
                if ips:
                    evidence += " 出口：" + "、".join(mask_ip(value) for value in ips)
            for column, text in enumerate((UPSTREAM_ITEMS[item["id"]], labels[state], evidence)):
                cell = QTableWidgetItem(text)
                cell.setToolTip(evidence)
                if column == 1:
                    cell.setForeground(QColor(COLORS[colors[state]]))
                self.upstream_table.setItem(row, column, cell)
        self.upstream_table.resizeRowsToContents()

    def read_dns_runtime(self):
        if (self.demo or self._closing or self.inspection_running or self.processes
                or not self.installed_config or self.installed_config.proxy_mode != "external"
                or not (self.status_data or {}).get("kernel_ok")):
            return
        self.report("DNS 运行配置位于 root 管理目录，需要在系统终端输入一次本机管理员密码。软件只读固定 DNS 字段，不修改代理；终端结束后自动更新检测结果。")
        try:
            self.launch("dns-admin", terminal_command(["/usr/bin/sudo", "/usr/bin/python3", "-I",
                        str(Path(__file__).with_name("external_audit.py")), "--read-runtime-dns"]))
        except ValueError as error:
            self.fail(error)

    def run_audit(self):
        if self.demo:
            return
        self.audit_data = audit_environment()
        findings = "\n".join(("需核对：" if item["level"] == "attention" else "信息：") + item["message"]
                             for item in self.audit_data["findings"])
        env = self.audit_data["environment"]
        self.audit_summary.setText(findings + f"\n面板 locale：{env['locale']}；时区缩写：{', '.join(env['timezone_names'])}。\n"
                                   "本结果只覆盖当前面板进程；专用窗口由启动器重建环境，客户端与项目设置尚未核对。")
        self.report("离线环境自检完成。原始代理 URL、认证信息和 API Key 未进入日志或报告。")
        self.render_inspection()

    def observe_egress(self, *, after=None):
        if self.demo:
            return
        if "egress" in self.processes:
            if callable(after):
                self.processes["egress"]["waiters"].append(after)
            return
        if not Path(CLI).is_file():
            self.fail("请先在连接配置中安装 v0.4.0 或更新的系统组件。")
            return
        self.egress_summary.setText("正在通过受保护环境观测 ipify 出口；本次结果尚未产生…")
        self.egress_data = None
        started_policy = self.state_signature
        self.report("开始主动出口观测：仅联系 api.ipify.org，不读取或使用 Claude 账号。")

        def done(code, text):
            self.egress_change = None
            self.egress_data = None
            if self.state_signature != started_policy:
                self.report("观测期间隔离状态发生变化，已丢弃本次结果；请刷新后重新观测。")
                self.render_egress()
                return
            try:
                result = json.loads(text)
                if (not isinstance(result, dict) or result.get("target") != EGRESS_TARGET
                        or result.get("scope") != "protected_namespace_to_ipify_only"
                        or result.get("status") not in ("complete", "partial", "failed")
                        or (code and result.get("status") == "complete")):
                    raise ValueError()
                self.egress_data = result
                if not code and result["status"] == "complete":
                    saved = self.history.record(result)
                    self.egress_history = saved["records"]
                    self.egress_change = saved["changed_since_previous"]
                    self.egress_data["changed_since_previous"] = self.egress_change
                    self.report("出口观测完成；相同代理配置下检测到出口变化。" if self.egress_change else
                                "出口观测完成，已保存本机历史。相同结果不能保证长期稳定。")
                else:
                    self.report("出口观测不完整，未写入历史；不会将旧的成功记录视为本次结果。")
            except (ValueError, TypeError, KeyError, OSError):
                if not isinstance(self.egress_data, dict) or self.egress_data.get("status") != "complete":
                    self.egress_data = {"status": "failed", "observed_ips": []}
                self.report("出口观测或历史保存未完成。请核对组件版本、代理连通性及本机历史文件权限。")
            if self.egress_data and "checked_at" not in self.egress_data:
                self.egress_data.update(checked_at=timestamp(), target=EGRESS_TARGET)
            self.render_egress()
            self.render_inspection()
        self.command("egress", [CLI, "egress"], done, timeout=90000, after=after)

    def render_egress(self):
        current = self.egress_data or {}
        addresses = current.get("observed_ips", [])
        shown = [mask_ip(ip) if self.hide_ip.isChecked() else ip for ip in addresses]
        if current.get("status") == "complete":
            change = "与上次同配置观测不同；请核对代理出口。" if self.egress_change else \
                     "与上次同配置观测相同。" if self.egress_change is False else "暂无可比较的同配置历史。"
            stable = "两次采样相同。" if current.get("stable_during_sample") else "两次采样出现不同出口。"
            self.egress_summary.setText("观测出口：" + ", ".join(shown) + "\n" + stable + change +
                                        "\n仅代表检测服务所见，不证明 Anthropic 出口或账号安全。")
        elif current:
            self.egress_summary.setText("本次出口观测未完整完成；请检查代理、TLS 或检测服务，旧历史不能作为本次通过依据。")
        else:
            self.egress_summary.setText("尚未观测，或隔离策略变化后需要重新观测；不会在后台自动查询出口。")
        entries = list(reversed(self.egress_history))
        self.history_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            ips = [mask_ip(ip) if self.hide_ip.isChecked() else ip for ip in entry["ips"]]
            for column, text in enumerate((entry["checked_at"], ", ".join(ips), "相同" if entry["stable_during_sample"] else "不同")):
                self.history_table.setItem(row, column, QTableWidgetItem(text))

    def clear_history(self):
        if self.demo:
            return
        try:
            self.history.clear()
            self.egress_history = []
            self.egress_change = None
            self.render_egress()
            self.report("本机出口历史已清除。")
        except (OSError, ValueError):
            self.fail("历史未清除：文件权限或格式不符合要求，请检查本机 diagnostics 目录。")

    def export_report(self):
        if self.demo:
            self.fail("演示模式没有实际检测结果，不能导出验收报告。")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "导出脱敏诊断报告", "claude-protect-report.json", "JSON (*.json)")
        if not filename:
            return
        try:
            result = diagnostic_report(status=self.status_data, keyring=self.keyring_data, probe=self.probe_data,
                                       audit=self.audit_data, egress=self.egress_data, history=self.egress_history,
                                       streaming=self.streaming_data)
            result["inspection"] = self.inspection_snapshot()
            result["external_proxy"] = upstream_report(self.upstream_data)
            save_report(filename, result)
            self.report("已导出白名单诊断报告；未包含原始日志、环境变量值、代理凭据或完整出口 IP。IP 前缀仍可能识别网络。")
        except (OSError, ValueError):
            self.fail("报告未保存。请选择新的文件名，避免覆盖符号链接、共享文件或其他用户的文件。")

    def render_core(self):
        ready = bool(self.status_data and self.status_data.get("kernel_ok"))
        managed = ready and self.status_data.get("upstream_managed") is True
        probe_ok = bool(self.probe_data and self.probe_data.get("passed"))
        checks = self.probe_data.get("checks", {}) if probe_ok else {}
        dns_ok = probe_ok and all(checks.get(key) is True for key in ("udp_dns_denied", "tcp_dns_denied", "system_dns_denied"))
        stream = self.streaming_data or {}
        if not stream and "streaming" not in self.processes:
            self.stream_summary.setText("尚未运行，或策略变化后需要重新验证。主动访问 httpbin 的约 20 秒滴流样本，不代表真实 Claude SSE / WebSocket 已验收。")
        stream_state = {"passed": "本次滴流样本通过；真实 Claude 会话待验收",
                        "inconclusive": "本次无法确认流式时序；可能被缓冲",
                        "failed": "本次未通过；检查代理或检测服务"}.get(stream.get("status"), "已实现检查入口；尚未运行样本")
        route = "应用与代理服务规则已核对；实际出口见下方观测" if managed else \
                "应用侧已核对；外部代理自身 DNS / 出口未受控" if ready else "已有实现；内核状态尚未核对"
        self.core_summary.setText("DNS 防旁路：" + ("本次应用侧阻断探测通过；抓包待验收" if dns_ok else "应用侧已有实现；Ubuntu 阻断探测与抓包待验收") +
                                 "\nIPv6 约束：" + ("本次直连阻断探测通过" if probe_ok and checks.get("direct_ipv6_denied") is True else "仅在隔离环境内禁用；实机探测待验收") +
                                 "\n明确代理路径：" + route +
                                 "\n断线阻断：已有默认丢弃与禁止直连；停代理 / relay 故障注入仍待实机验收" +
                                 "\n长连接 / 流式通道：" + stream_state)

    def check_stream(self, *, after=None):
        if self.demo:
            return
        if "streaming" in self.processes:
            if callable(after):
                self.processes["streaming"]["waiters"].append(after)
            return
        if not Path(CLI).is_file():
            self.fail("请先安装 v0.4.0 或更新的系统组件。")
            return
        self.streaming_data = None
        started_policy = self.state_signature
        self.render_core()
        self.stream_summary.setText("正在通过隔离环境访问 httpbin：检查连接复用，并观察约 20 秒滴流。最长执行时间受限，面板可继续操作…")
        self.report("开始主动滴流验证：只访问 httpbin，不读取 Claude 凭据，也不发送提示词。")

        def done(code, text):
            try:
                result = json.loads(text)
                if (self.state_signature != started_policy or not isinstance(result, dict)
                        or result.get("target") != STREAM_TARGET or result.get("scope") != "generic_httpbin_https_stream_only"
                        or result.get("status") not in ("passed", "inconclusive", "failed")
                        or (code and result.get("status") == "passed")):
                    raise ValueError()
                self.streaming_data = result
            except (ValueError, TypeError):
                self.streaming_data = {"status": "failed", "target": STREAM_TARGET, "checked_at": timestamp()}
            result = self.streaming_data
            if result["status"] == "passed":
                reuse = "本次观察到连接复用。" if result.get("connection_reused") else "本次未观察到连接复用。"
                self.stream_summary.setText(f"滴流样本通过，持续收包跨度 {result.get('stream_span_ms', 0) / 1000:.1f} 秒。" + reuse + "真实 Claude SSE / WebSocket 仍待验收。")
            elif result["status"] == "inconclusive":
                self.stream_summary.setText("响应收到，但持续到达的时序未被观察到，可能存在缓冲；不会记为流式验证通过。")
            else:
                self.stream_summary.setText("本次样本未通过。可能是代理、证书、检测服务或隔离状态发生变化；不能据此判断 Claude 账号被封。")
            self.report("滴流验证结束：" + result["status"] + "。本次不评估账号安全。")
            self.render_core()
            self.render_inspection()
        self.command("streaming", [CLI, "stream-check"], done, timeout=90000, after=after)

    def inspection_snapshot(self):
        return checklist(installed=CONFIG.exists() if not self.demo else False, status=self.status_data,
                         status_checked_at=self.status_checked_at, keyring=self.keyring_data, probe=self.probe_data,
                         audit=self.audit_data, egress=self.egress_data, streaming=self.streaming_data,
                         upstream=self.upstream_data, preview=self.demo)

    def render_inspection(self):
        result = self.inspection_snapshot()
        counts = result["counts"]
        self.inspection_summary.setText(f"{counts['fix']} 项需要处理 · {counts['warn']} 项需要核对 · "
                                        f"{counts['pending']} 项尚未验证 · {counts['pass']} 项本次通过")
        self.inspection_hint.setText("界面演示：进入环境检测页查看检查项目与设置入口。" if self.demo else
                                    f"环境检测提醒：{counts['fix']} 项需要处理，{counts['warn']} 项需要核对，"
                                    f"{counts['pending']} 项尚未验证。配置完成后，可先运行一轮环境检测。")
        rows = result["items"]
        self.inspection_table.setRowCount(len(rows))
        colors = {"pass": COLORS["good"], "fix": COLORS["bad"], "warn": COLORS["warn"], "pending": COLORS["neutral"]}
        for row, item in enumerate(rows):
            for column, text in enumerate((item["title"], LABELS[item["state"]], item["evidence"] + "\n" + item["advice"])):
                cell = QTableWidgetItem(text)
                cell.setToolTip(item["evidence"] + "\n" + item["advice"])
                if column == 1:
                    cell.setForeground(QColor(colors[item["state"]]))
                self.inspection_table.setItem(row, column, cell)
        self.inspection_table.resizeRowsToContents()
        while self.advice_layout.count():
            old = self.advice_layout.takeAt(0)
            if old.widget():
                old.widget().deleteLater()
        names = {"configure": "去连接配置", "refresh": "刷新状态", "diagnostics": "查看诊断",
                 "probe": "运行联网验证", "keyring": "检查密钥链", "keyring-settings": "打开密码和密钥",
                 "egress": "观测出口", "streaming": "验证流式通道", "audit": "离线检查",
                 "audit-details": "查看具体配置提示", "netcoffee": "打开受保护检测页", "upstream": "检测外部代理"}
        for item in result["recommendations"][:6]:
            frame = QWidget()
            row = QHBoxLayout(frame)
            row.setContentsMargins(0, 0, 0, 0)
            text = label(item["title"] + "：" + item["advice"], "muted", True)
            row.addWidget(text, 1)
            action = item["action"]
            control = button(names[action], lambda checked=False, target=action: self.inspection_action(target))
            control.setEnabled(not self.demo and not self.inspection_running)
            row.addWidget(control)
            self.advice_layout.addWidget(frame)
        self.inspection_start.setEnabled(not self.demo and not self.inspection_running and not self._closing and "restore" not in self.background)
        self.inspection_stop.setEnabled(self.inspection_running and not self.inspection_cancelled)

    def inspection_action(self, action):
        if self.demo or self.inspection_running or self._closing:
            return
        actions = {"configure": lambda: self.navigate(1), "diagnostics": lambda: self.navigate(2),
                   "audit-details": lambda: self.navigate(2), "refresh": self.refresh, "probe": self.run_probe,
                   "keyring": self.check_keyring, "keyring-settings": self.open_keyring_settings,
                   "egress": self.observe_egress, "streaming": self.check_stream, "audit": self.run_audit,
                   "netcoffee": self.open_netcoffee, "upstream": self.open_upstream_check}
        if action in ("probe", "keyring", "egress", "streaming") and not (self.status_data or {}).get("kernel_ok"):
            self.navigate(1)
            self.footer.setText("先完成组件安装并刷新隔离状态，再执行此项检查。")
            return
        if action in actions:
            actions[action]()

    def open_netcoffee(self):
        if self.demo or self._closing:
            return
        if not (self.status_data or {}).get("kernel_ok") or not Path(CLI).is_file():
            self.navigate(1)
            self.footer.setText("先安装并核对隔离服务；检测页面只通过受保护浏览器打开。")
            return
        self.launch("browser-coffee", [CLI, "browser", "https://ip.net.coffee/claude/"])

    def open_keyring_settings(self):
        if self.demo or self._closing:
            return
        manager = Path("/usr/bin/seahorse")
        if not manager.is_file():
            self.fail("请在 Ubuntu 应用菜单打开「密码和密钥」，创建并解锁默认密钥链。若未安装，可在系统终端安装 seahorse，再返回检查。")
            return
        self.launch("keyring-settings", [str(manager)])

    def start_inspection(self):
        if self.demo or self.inspection_running or self._closing or "restore" in self.background:
            return
        self.navigate(3)
        self.inspection_running = True
        self.inspection_cancelled = False
        self.inspection_completed = 0
        self.inspection_steps = [("隔离状态", self.refresh), ("密钥链通道", self.check_keyring),
                                 ("DNS / IPv6 / 连通性", self.run_probe), ("实际出口", self.observe_egress),
                                 ("外部代理", self.run_upstream_check)]
        if self.include_stream.isChecked():
            self.inspection_steps.append(("20 秒流式样本", self.check_stream))
        self.inspection_progress.setRange(0, len(self.inspection_steps))
        self.inspection_progress.setValue(0)
        self.run_audit()
        self.report("开始一轮环境检测：只执行列出的检查，不自动修改系统配置。")
        self._inspection_next()

    def _inspection_next(self):
        if not self.inspection_running or self._closing:
            return
        if self.inspection_cancelled:
            self._finish_inspection("已停止后续步骤，已有结果保留；尚未执行的项目不会显示为通过。")
            return
        if self.inspection_completed and not (self.status_data or {}).get("kernel_ok"):
            self._finish_inspection("隔离未就绪，已完成离线检查并跳过联网步骤。请按下方建议处理。")
            return
        if self.inspection_completed and not Path(CLI).is_file():
            self._finish_inspection("配套命令已不可用，已停止后续步骤；请检查安装状态。")
            return
        if self.inspection_steps and self.inspection_steps[0][0] in ("实际出口", "外部代理", "20 秒流式样本") and not (self.probe_data or {}).get("passed"):
            self._finish_inspection("基础联网验证未通过，已跳过后续联网检查。请先检查代理与诊断日志。")
            return
        if not self.inspection_steps:
            self._finish_inspection("本轮已结束。请查看逐项结果和设置建议；未验证的浏览器项目仍需单独核对。")
            return
        name, operation = self.inspection_steps.pop(0)
        self.inspection_run_note.setText("正在检测：" + name + "。可以停止后续步骤，当前有时限的检查会先结束。")
        self.render_inspection()

        def completed():
            if self._closing:
                return
            self.inspection_completed += 1
            self.inspection_progress.setValue(self.inspection_completed)
            self._inspection_next()
        operation(after=completed)

    def _finish_inspection(self, note):
        self.inspection_running = False
        self.inspection_steps = []
        self.inspection_run_note.setText(note)
        self.render_inspection()
        self.report(note)

    def cancel_inspection(self):
        if self.inspection_running:
            self.inspection_cancelled = True
            self.inspection_run_note.setText("已请求停止；当前检查结束后不再启动后续步骤。")
            self.render_inspection()

    def closeEvent(self, event):
        self._closing = True
        self.inspection_cancelled = True
        super().closeEvent(event)

    def launch(self, key, argv):
        """Detached child: closing this panel must not terminate protected apps."""
        if self.demo or key in self.background:
            return
        if "restore" in self.background:
            self.footer.setText("还原正在执行，请等待终端结束后再启动应用或安装。")
            return
        self.background.add(key)
        self.report("已提交启动请求。请查看应用窗口或系统终端；实际结果仍由启动器与状态检查决定。")
        self.render()

        def worker():
            try:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                tail = bytearray()
                # Drain continuously, retaining at most 64 KiB in memory.
                with process.stdout as output:
                    while block := output.read(4096):
                        tail.extend(block)
                        if len(tail) > 65536:
                            del tail[:-65536]
                code = process.wait()
                self.events.put((key, code, tail.decode("utf-8", "replace")))
            except OSError as error:
                self.events.put((key, -1, str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def _drain_events(self):
        while not self.events.empty():
            key, code, text = self.events.get()
            self.background.discard(key)
            self.report(f"{key}：命令已结束（退出码 {code}）。" + ("\n" + text if text.strip() else ""))
            if key == "restore":
                if code == 0 and not CONFIG.exists():
                    self.restoration_note = "配套配置已移除。网络清理核对结果以终端输出为准；再次保护需要重新安装组件。"
                elif code == 0:
                    self.restoration_note = "配置仍存在：操作可能尚在终端执行，或未完成。请查看终端并刷新状态。"
                else:
                    self.restoration_note = "还原未完成或被取消；请查看终端错误。保留的规则或配置需继续核对。"
            if key == "dns-admin" and code == 0:
                self.refresh(after=self.run_upstream_check)
            else:
                self.refresh()

    def open_code(self):
        try:
            self.launch("code", launch_command(self.folder.text()))
        except ValueError as error:
            self.fail(error)

    def install_dependencies(self):
        try:
            self.launch("admin", terminal_command(["/usr/bin/sudo", "/usr/bin/apt-get", "install",
                       "python3", "iproute2", "nftables", "util-linux", "sudo", "xdg-dbus-proxy",
                       "libglib2.0-bin", "libsecret-1-0", "gnome-keyring"]))
        except ValueError as error:
            self.fail(error)

    def install_core(self):
        if self.demo:
            return
        if "restore" in self.background:
            self.fail("还原操作正在执行，请等待终端结束后再安装。")
            return
        try:
            argv = install_command(self.release.text(), user=self.user.text(), mode=self.mode.currentData(),
                                   local_port=self.local_port.text(), ip=self.ip.text(), port=self.port.text(),
                                   tls_name=self.tls_name.text(), auth=self.auth.isChecked())
            self.launch("admin", terminal_command(argv))
        except (ValueError, KeyError) as error:
            self.fail(error)

    def uninstall_core(self):
        if self.demo:
            return
        if "restore" in self.background:
            self.footer.setText("还原终端已打开，请在该终端查看进度。")
            return
        if self.inspection_running or self.processes or "admin" in self.background:
            self.fail("请先停止本轮检测，等待当前检查或安装结束，再执行还原。")
            return
        if not CONFIG.exists():
            self.restoration_note = "未发现已安装的系统配置，无需还原；如曾手动删除组件，请按说明核对残留。"
            self.restore_status.setText(self.restoration_note)
            return
        installed_script = Path("/usr/local/share/claude-protect/uninstall.py")
        source_script = Path(self.release.text()).resolve() / "scripts/uninstall.py"
        script = installed_script if installed_script.is_file() else source_script
        if not script.is_file():
            self.fail("请先在连接配置中选择完整发行包目录。")
            return
        answer = QMessageBox.question(self, "还原系统配置", "请先关闭受保护 VS Code、浏览器及其后台进程。\n\n将移除本项目网络隔离、系统服务、防火墙规则和受控代理凭据；保留项目、Claude 登录资料、专用窗口数据与外部代理配置。\n\n还原后需重新安装组件才能继续使用保护。将在系统终端输入管理员密码。")
        if answer == QMessageBox.StandardButton.Yes:
            try:
                self.restoration_note = "已请求还原，请在系统终端输入管理员密码并查看清理核对结果。"
                self.restore_status.setText(self.restoration_note)
                self.restore_button.setEnabled(False)
                self.restore_top_button.setEnabled(False)
                self.launch("restore", terminal_command(["/usr/bin/sudo", "/usr/bin/python3", str(script)]))
            except ValueError as error:
                self.fail(error)

    def copy_log(self):
        QApplication.clipboard().setText(self.log.toPlainText())
        self.footer.setText("会话日志已复制。")

    def add_shortcut(self):
        if self.demo:
            self.fail("演示模式不修改系统或应用菜单。")
            return
        root = Path(__file__).resolve().parents[2]
        script = root / "scripts/gui.py"
        argv = [sys.executable, str(script)] if script.is_file() else [sys.executable, CLI, "gui"]
        applications = Path.home() / ".local/share/applications"
        applications.mkdir(parents=True, exist_ok=True)
        target = applications / "claude-protect-panel.desktop"
        if target.is_symlink():
            self.fail("拒绝覆盖符号链接快捷方式。")
            return
        target.write_text("[Desktop Entry]\nType=Application\nName=Claude Protect — 控制面板\n"
                          "Comment=Claude Protect PySide6 desktop panel\nExec=" +
                          " ".join(desktop_quote(part) for part in argv) +
                          "\nIcon=" + (str(PANEL_ICON) if PANEL_ICON.is_file() else "security-high") +
                          "\nTerminal=false\nCategories=Network;\nStartupNotify=true\n", encoding="utf-8")
        self.report("已添加应用菜单入口。请保留解压目录与 Python 虚拟环境，以便下次启动。")
        QMessageBox.information(self, "已添加", "在应用菜单搜索 Claude Protect — 控制面板。请保留解压目录与虚拟环境。")

    def open_guide(self):
        source = Path(__file__).resolve().parents[2] / "README.md"
        guide = source if source.is_file() else Path("/usr/local/share/claude-protect/README.md")
        if guide.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(guide)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Claude Protect PySide6 desktop panel")
    parser.add_argument("--demo", action="store_true", help="preview only; no system actions, works on macOS too")
    args = parser.parse_args(argv)
    if not args.demo and (sys.platform != "linux" or os.geteuid() == 0):
        parser.error("请在 Ubuntu 桌面用普通用户运行；其他系统仅支持 --demo 界面演示。")
    application = QApplication.instance() or QApplication([sys.argv[0]])
    application.setApplicationName("Claude Protect")
    application.setDesktopFileName("claude-protect-panel")
    icon = QIcon(str(PANEL_ICON)) if PANEL_ICON.is_file() else QIcon()
    if not icon.isNull():
        application.setWindowIcon(icon)
    application.setStyle("Fusion")
    font = QFont()
    font.setFamilies(["Noto Sans CJK SC", "PingFang SC", "Microsoft YaHei", "sans-serif"])
    font.setPointSize(10)
    application.setFont(font)
    window = Panel(demo=args.demo)
    screen = application.primaryScreen()
    if screen:
        available = screen.availableGeometry()
        window.resize(min(1220, available.width() - 50), min(880, available.height() - 60))
    if icon.isNull():
        pixmap = QPixmap(216, 192)
        pixmap.fill(Qt.GlobalColor.transparent)
        window.robot.render(pixmap)
        icon = QIcon(pixmap)
    window.setWindowIcon(icon)
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
