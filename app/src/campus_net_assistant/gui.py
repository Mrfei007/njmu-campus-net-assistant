from __future__ import annotations

import ctypes
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import (QPointF, QSize, Qt, QThread, QTime, QTimer, QObject, QUrl,
                            Signal, Slot)
from PySide6.QtGui import (QAction, QColor, QCloseEvent, QDesktopServices, QIcon, QPainter,
                           QPainterPath, QPen, QPixmap)
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStyle,
    QSystemTrayIcon,
    QTimeEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .config import (
    APP_DIR,
    CONNECTION_MODE_DORM_ETHERNET,
    CONNECTION_MODE_WORKSTATION_RUIJIE,
    CONNECTION_MODE_WIRELESS,
    apply_schedule,
    load_config,
    save_config,
)
from .credentials import load as load_credentials
from .credentials import save as save_credentials
from .logging_redacted import event
from .monitor_state import (
    clear_suppression as clear_monitor_suppression,
    load as load_monitor_state,
    suppression_remaining_seconds,
)
from .native_backend_state import (
    fallback_status,
    primary_status,
)
from .npcap_backend import npcap_detected
from .product import PRODUCT_NAME, PRODUCT_VERSION
from .scheduler import (
    install_with_elevation,
    installed_task_names,
    is_admin,
    logout_network_with_elevation,
    remove_all_tasks_with_elevation,
    validate_login_with_elevation,
)
from .status import read as read_status


NPCAP_DOWNLOAD_URL = "https://npcap.com/dist/npcap-1.89.exe"


OPERATOR_OPTIONS = ("电信", "移动", "联通", "校园网")
CONNECTION_MODE_OPTIONS = (
    ("全校无线网", CONNECTION_MODE_WIRELESS),
    ("宿舍有线网", CONNECTION_MODE_DORM_ETHERNET),
    ("工位有线网", CONNECTION_MODE_WORKSTATION_RUIJIE),
)


def _password_eye_icon(slashed: bool) -> QIcon:
    """Return a compact monochrome reveal-password icon."""
    pixmap = QPixmap(24, 24)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    color = QColor("#536273")
    painter.setPen(QPen(color, 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    eye = QPainterPath()
    eye.moveTo(2.5, 12)
    eye.cubicTo(6.0, 5.7, 18.0, 5.7, 21.5, 12)
    eye.cubicTo(18.0, 18.3, 6.0, 18.3, 2.5, 12)
    painter.drawPath(eye)
    painter.drawEllipse(QPointF(12, 12), 2.8, 2.8)
    if slashed:
        painter.setPen(QPen(QColor("#ffffff"), 4.0, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(QPointF(4.0, 4.0), QPointF(20.0, 20.0))
        painter.setPen(QPen(color, 1.9, Qt.SolidLine, Qt.RoundCap))
        painter.drawLine(QPointF(4.0, 4.0), QPointF(20.0, 20.0))
    painter.end()
    return QIcon(pixmap)


class PopupWheelComboBox(QComboBox):
    """Only change the selection by wheel while the popup is open."""

    def wheelEvent(self, event) -> None:
        if self.view().isVisible():
            super().wheelEvent(event)
            return
        event.ignore()


class LoginWorker(QObject):
    finished = Signal(bool)

    def __init__(self, config, action: str) -> None:
        super().__init__()
        self.config = config
        self.action = action

    @Slot()
    def run(self) -> None:
        try:
            if self.action == "logout":
                ok = logout_network_with_elevation(self.config)
            elif self.action == "dorm_static_script_survey":
                from .controller import collect_dorm_static_script_survey

                ok = collect_dorm_static_script_survey(self.config)
            else:
                ok = validate_login_with_elevation(self.config)
            self.finished.emit(bool(ok))
        except Exception as error:
            stage = (
                "dorm-static-script-survey"
                if self.action == "dorm_static_script_survey"
                else (
                    "manual-network-logout-elevation"
                    if self.action == "logout"
                    else "manual-login-validation-elevation"
                )
            )
            event(
                stage,
                False,
                f"{type(error).__name__}: {error}",
            )
            self.finished.emit(False)


class NativeVerifyWorker(QObject):
    finished = Signal(dict)

    def __init__(self, config) -> None:
        super().__init__()
        self.config = config

    @Slot()
    def run(self) -> None:
        from .controller import verify_native_primary
        try:
            result = verify_native_primary(self.config)
        except Exception as error:
            result = {"success": False, "message": f"{type(error).__name__}: {error}"}
        self.finished.emit(result if isinstance(result, dict) else {
            "success": False, "message": "验证未返回可识别结果"})


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(PRODUCT_NAME)
        self.product_version = PRODUCT_VERSION
        self._settings_dirty = False
        self.resize(1040, 760)
        self.setMinimumSize(860, 600)
        self._allow_close = False
        self.login_thread: QThread | None = None
        self.login_worker: LoginWorker | None = None
        self.verify_thread: QThread | None = None
        self.verify_worker: NativeVerifyWorker | None = None
        self.manual_action = ""
        self.config = load_config()
        self._task_names: list[str] = []
        self._task_refresh_counter = 0
        self._last_auth_alert_time = ""
        self._credentials_available = False
        self._last_status: dict = {}

        root = QWidget(self)
        root.setObjectName("appRoot")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        page = QWidget()
        page.setObjectName("page")
        layout = QVBoxLayout(page)
        self.page_layout = layout
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(16)

        scroll = QScrollArea(self)
        self.content_scroll = scroll
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        root_layout.addWidget(scroll, 1)
        self.root_layout = root_layout
        self.setCentralWidget(root)

        status_card, status_layout = self._make_card()
        self.status_card = status_card
        status_header = QHBoxLayout()
        status_header.setContentsMargins(0, 0, 0, 0)
        self.status_title = self._section_title("运行状态")
        status_header.addWidget(self.status_title)
        status_header.addStretch(1)
        self.status_badge = QLabel("尚未运行")
        self.status_badge.setObjectName("statusBadge")
        status_header.addWidget(self.status_badge)
        status_layout.addLayout(status_header)
        self.status_label = QLabel("尚未运行")
        self.status_label.setObjectName("statusMessage")
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)
        self.monitor_label = QLabel("监测：正在读取")
        self.monitor_label.setObjectName("metaText")
        self.task_label = QLabel("自动化任务：正在读取")
        self.task_label.setObjectName("metaText")
        status_meta = QHBoxLayout()
        status_meta.setContentsMargins(0, 0, 0, 0)
        status_meta.setSpacing(18)
        status_meta.addWidget(self.monitor_label)
        status_meta.addWidget(self.task_label)
        status_meta.addStretch(1)
        status_layout.addLayout(status_meta)
        self.next_action_label = QLabel()
        self.next_action_label.setObjectName("nextAction")
        status_layout.addWidget(self.next_action_label)
        layout.addWidget(status_card)

        automation_card, automation_layout = self._make_card("自动化功能")
        self.automation_card = automation_card
        self.auto_connect_on_startup = QCheckBox("开机后自动联网")
        self.auto_connect_on_startup.setChecked(self.config.auto_connect_on_startup)
        self.auto_connect_on_startup.setToolTip("按当前连接模式自动联网并持续监测；不依赖每日唤醒，也不会唤醒电脑。")
        automation_layout.addWidget(self.auto_connect_on_startup)
        self.wake_enabled = QCheckBox("每天定时唤醒")
        self.wake_enabled.setChecked(self.config.wake_enabled)
        (
            self.wake_time_control,
            self.wake_time,
            self.wake_time_up_button,
            self.wake_time_down_button,
        ) = self._make_time_adjuster(self.config.wake_time, "唤醒时间")
        self.wake_disabled_label = QLabel("已关闭")
        self.wake_disabled_label.setObjectName("disabledValue")
        wake_row = QHBoxLayout()
        wake_row.setContentsMargins(0, 0, 0, 0)
        wake_row.addWidget(self.wake_enabled)
        wake_row.addStretch(1)
        wake_row.addWidget(self.wake_disabled_label)
        wake_row.addWidget(self.wake_time_control)
        automation_layout.addLayout(wake_row)

        self.hibernate_enabled = QCheckBox("每天定时休眠")
        self.hibernate_enabled.setChecked(self.config.hibernate_enabled)
        (
            self.sleep_time_control,
            self.sleep_time,
            self.sleep_time_up_button,
            self.sleep_time_down_button,
        ) = self._make_time_adjuster(self.config.sleep_time, "休眠时间")
        self.sleep_disabled_label = QLabel("已关闭")
        self.sleep_disabled_label.setObjectName("disabledValue")
        sleep_row = QHBoxLayout()
        sleep_row.setContentsMargins(0, 0, 0, 0)
        sleep_row.addWidget(self.hibernate_enabled)
        sleep_row.addStretch(1)
        sleep_row.addWidget(self.sleep_disabled_label)
        sleep_row.addWidget(self.sleep_time_control)
        automation_layout.addLayout(sleep_row)

        self.schedule_hint = QLabel()
        self.schedule_hint.setObjectName("modeHint")
        self.schedule_hint.setWordWrap(True)
        automation_layout.addWidget(self.schedule_hint)

        manual_card, manual_layout = self._make_card("网络连接")
        self.manual_card = manual_card
        manual_copy = QLabel(
            "根据当前联网状态显示可执行操作；每次认证只提交一轮并验证真实联网。"
        )
        manual_copy.setObjectName("secondaryText")
        manual_copy.setWordWrap(True)
        manual_layout.addWidget(manual_copy)
        manual_row = QHBoxLayout()
        manual_row.setContentsMargins(0, 0, 0, 0)
        self.native_verify_button = QPushButton("原生认证检查并验证")
        self.native_verify_button.setObjectName("primaryButton")
        self.native_verify_button.clicked.connect(self.run_native_verification)
        self.reauthenticate_button = QPushButton("断开校园网认证")
        self.reauthenticate_button.setObjectName("warningButton")
        self.login_validate_button = QPushButton("立即认证并检查联网")
        self.login_validate_button.setObjectName("primaryButton")
        self.network_details_button = QPushButton("查看联网详情")
        self.network_details_button.setObjectName("compactButton")
        for button in (
            self.native_verify_button,
            self.reauthenticate_button,
            self.login_validate_button,
            self.network_details_button,
        ):
            button.setMinimumHeight(38)
        self.login_button = self.reauthenticate_button
        manual_row.addWidget(self.native_verify_button, 1)
        manual_row.addWidget(self.reauthenticate_button, 1)
        manual_row.addWidget(self.login_validate_button, 1)
        manual_row.addWidget(self.network_details_button, 1)
        manual_layout.addLayout(manual_row)
        self.native_verify_hint = QLabel()
        self.native_verify_hint.setObjectName("modeHint")
        self.native_verify_hint.setWordWrap(True)
        self.native_verify_hint.setMinimumHeight(32)
        self.native_verify_hint.hide()
        manual_layout.addWidget(self.native_verify_hint)
        self.dorm_script_survey_button = QPushButton("收集宿舍门户静态脚本…")
        self.dorm_script_survey_button.setObjectName("linkButton")
        self.dorm_script_survey_button.setToolTip(
            "保持宿舍有线网在线，只读下载最近一次完整观察中出现的官方静态 JavaScript；不会登录或注销。"
        )
        manual_layout.addWidget(self.dorm_script_survey_button)

        details_card, details_layout = self._make_card("连接设置")
        self.account_card = details_card
        self.details_container = QWidget()
        details_container_layout = QVBoxLayout(self.details_container)
        details_container_layout.setContentsMargins(0, 0, 0, 0)
        details_container_layout.setSpacing(12)

        credentials_row = QHBoxLayout()
        credentials_row.setContentsMargins(0, 0, 0, 0)
        self.credentials_hint = QLabel()
        self.credentials_hint.setWordWrap(True)
        credentials_row.addWidget(self.credentials_hint, 1)
        self.edit_credentials_button = QPushButton("重新输入")
        self.edit_credentials_button.setObjectName("compactButton")
        credentials_row.addWidget(self.edit_credentials_button)
        details_container_layout.addLayout(credentials_row)

        self.username = QLineEdit()
        self.username.setPlaceholderText("请输入校园网账号")
        self.password = QLineEdit()
        self.password.setPlaceholderText("请输入校园网密码")
        self.password.setEchoMode(QLineEdit.Password)
        self.password_visibility_button = QToolButton()
        # 图标表达当前状态：斜线眼睛表示密码仍被隐藏为圆点；
        # 普通眼睛表示密码当前可见。
        self.password_visibility_button.setIcon(_password_eye_icon(True))
        self.password_visibility_button.setIconSize(QSize(20, 20))
        self.password_visibility_button.setObjectName("passwordVisibilityButton")
        self.password_visibility_button.setCheckable(True)
        self.password_visibility_button.setToolTip("显示密码")
        self.password_visibility_button.setAccessibleName("显示密码")
        self.password_visibility_button.setFixedWidth(38)
        password_row = QWidget()
        password_layout = QHBoxLayout(password_row)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(6)
        password_layout.addWidget(self.password, 1)
        password_layout.addWidget(self.password_visibility_button)
        self.credentials_editor = QWidget()
        credentials_form = QFormLayout(self.credentials_editor)
        credentials_form.setContentsMargins(0, 0, 0, 0)
        credentials_form.setHorizontalSpacing(14)
        credentials_form.setVerticalSpacing(10)
        credentials_form.addRow("校园网账号：", self.username)
        credentials_form.addRow("校园网密码：", password_row)
        details_container_layout.addWidget(self.credentials_editor)

        settings_form = QFormLayout()
        settings_form.setContentsMargins(0, 0, 0, 0)
        settings_form.setHorizontalSpacing(14)
        settings_form.setVerticalSpacing(10)
        self.connection_mode = PopupWheelComboBox()
        for label, value in CONNECTION_MODE_OPTIONS:
            self.connection_mode.addItem(label, value)
        selected_mode = self.connection_mode.findData(self.config.connection_mode)
        self.connection_mode.setCurrentIndex(max(0, selected_mode))
        settings_form.addRow("连接方式：", self.connection_mode)
        self._last_connection_mode_index = self.connection_mode.currentIndex()
        self.connection_mode_hint = QLabel()
        self.connection_mode_hint.setObjectName("modeHint")
        self.connection_mode_hint.setWordWrap(True)
        settings_form.addRow("", self.connection_mode_hint)

        self.ruijie_path = QLineEdit(self.config.ruijie_path)
        self.ruijie_path.setPlaceholderText("请选择官方锐捷客户端 RuijieSupplicant.exe")
        self.ruijie_browse_button = QPushButton("浏览…")
        self.ruijie_browse_button.setAccessibleName("选择锐捷客户端")
        self.ruijie_path_row = QWidget()
        ruijie_path_layout = QHBoxLayout(self.ruijie_path_row)
        ruijie_path_layout.setContentsMargins(0, 0, 0, 0)
        ruijie_path_layout.addWidget(self.ruijie_path, 1)
        ruijie_path_layout.addWidget(self.ruijie_browse_button)
        self.ruijie_path_label = QLabel("锐捷客户端：")
        settings_form.addRow(self.ruijie_path_label, self.ruijie_path_row)

        self.ruijie_background_client_fallback = QCheckBox("锐捷驱动作为后备连接")
        self.ruijie_background_client_fallback.setChecked(self.config.rawether_fallback_enabled)
        self.ruijie_background_client_fallback.setToolTip(
            "默认关闭。勾选后可用官方锐捷客户端的 Rawether 驱动作为后备连接；"
            "不启动锐捷客户端，也不读取账号密码。必须先在“锐捷驱动检查”中通过只读检查。")
        self.rawether_check_button = QPushButton("锐捷驱动检查")
        self.rawether_check_button.clicked.connect(self.open_rawether_check)
        self.rawether_check_status = QLabel("未检查")
        self.rawether_check_status.setObjectName("metaText")
        rawether_row = QWidget()
        rawether_layout = QHBoxLayout(rawether_row)
        rawether_layout.setContentsMargins(0, 0, 0, 0)
        rawether_layout.addWidget(self.ruijie_background_client_fallback)
        rawether_layout.addWidget(self.rawether_check_button)
        rawether_layout.addWidget(self.rawether_check_status, 1)
        settings_form.addRow("", rawether_row)
        self.native_fallback_row = rawether_row

        self.operator = PopupWheelComboBox()
        self.operator.addItems(OPERATOR_OPTIONS)
        current_operator = self.config.portal.operator
        if current_operator in OPERATOR_OPTIONS:
            self.operator.setCurrentText(current_operator)
        self.operator_label = QLabel("运营商：")
        settings_form.addRow(self.operator_label, self.operator)

        self.keep_login_page_open = QCheckBox("联网后保留认证页面")
        self.keep_login_page_open.setChecked(self.config.keep_login_page_open)
        self.wireless_http_experimental = QCheckBox("实验：优先尝试无浏览器登录")
        self.wireless_http_experimental.setChecked(self.config.wireless_http_experimental)
        self.wireless_http_experimental.setToolTip(
            "仅用于全校无线网；页面结构不兼容时会在提交账号密码前回退到 Chrome 或 Edge。"
        )
        settings_form.addRow("", self.wireless_http_experimental)
        self.dorm_protocol_observer_enabled = QCheckBox("调查：宿舍门户轻量网络观察")
        self.dorm_protocol_observer_enabled.setChecked(self.config.dorm_protocol_observer_enabled)
        self.dorm_protocol_observer_enabled.setToolTip(
            "沿用普通登录入口，只记录脱敏网络事件和请求错误，不启用脚本调试或读取响应正文。"
            "记录位于 diagnostics\\dorm-protocol-observer；调查浏览器卡住时会自动切换普通登录。"
        )
        settings_form.addRow("", self.dorm_protocol_observer_enabled)
        self.start_uu = QCheckBox("联网后启动 UU 远程")
        self.start_uu.setChecked(self.config.start_uu)
        self.uu_path = QLineEdit(self.config.uu_path)
        self.uu_path.setPlaceholderText("请选择 UU 远程运行文件")
        self.uu_browse_button = QPushButton("浏览…")
        self.uu_browse_button.setAccessibleName("选择 UU 程序")
        self.uu_path_row = QWidget()
        uu_path_layout = QHBoxLayout(self.uu_path_row)
        uu_path_layout.setContentsMargins(0, 0, 0, 0)
        uu_path_layout.addWidget(self.uu_path, 1)
        uu_path_layout.addWidget(self.uu_browse_button)
        self.uu_path_label = QLabel("UU 程序路径：")
        details_container_layout.addLayout(settings_form)
        details_layout.addWidget(self.details_container)

        # 自动化功能按实际执行顺序排列：唤醒联网、启动 UU、定时休眠、
        # 是否保留认证页面。UU 路径只在开关启用时显示。
        automation_layout.insertWidget(2, self.start_uu)
        uu_automation_form = QFormLayout()
        uu_automation_form.setContentsMargins(0, 0, 0, 0)
        uu_automation_form.setHorizontalSpacing(14)
        uu_automation_form.addRow(self.uu_path_label, self.uu_path_row)
        automation_layout.insertLayout(3, uu_automation_form)
        automation_layout.insertWidget(5, self.keep_login_page_open)

        management_card, management_layout = self._make_card("停用与维护")
        self.management_card = management_card
        management_copy = QLabel(
            "停用后将停止后台监测并删除自动化任务，账号、配置、日志和程序文件不会删除。"
        )
        management_copy.setObjectName("secondaryText")
        management_copy.setWordWrap(True)
        management_layout.addWidget(management_copy)
        management_row = QHBoxLayout()
        management_row.setContentsMargins(0, 0, 0, 0)
        self.stop_automation_button = QPushButton("停用全部自动化…")
        self.stop_automation_button.setObjectName("warningButton")
        management_row.addStretch(1)
        management_row.addWidget(self.stop_automation_button)
        management_layout.addLayout(management_row)

        columns = QWidget()
        columns.setObjectName("contentColumns")
        columns_layout = QHBoxLayout(columns)
        columns_layout.setContentsMargins(0, 0, 0, 0)
        columns_layout.setSpacing(16)
        self.left_column = QWidget()
        self.left_column.setObjectName("leftColumn")
        left_layout = QVBoxLayout(self.left_column)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(16)
        left_layout.addWidget(manual_card)
        left_layout.addWidget(automation_card)
        left_layout.addStretch(1)
        self.right_column = QWidget()
        self.right_column.setObjectName("rightColumn")
        right_layout = QVBoxLayout(self.right_column)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)
        right_layout.addWidget(details_card)
        right_layout.addWidget(management_card)
        right_layout.addStretch(1)
        columns_layout.addWidget(self.left_column, 42)
        columns_layout.addWidget(self.right_column, 58)
        self.content_columns = columns
        layout.addWidget(columns)

        self.start_uu.toggled.connect(self.update_uu_controls)
        self.connection_mode.currentIndexChanged.connect(self.update_connection_mode_hint)
        self.ruijie_path.textChanged.connect(self.update_connection_mode_hint)
        self.ruijie_browse_button.clicked.connect(self.select_ruijie_path)
        self.uu_browse_button.clicked.connect(self.select_uu_path)
        self.wake_enabled.toggled.connect(self.update_schedule_controls)
        self.auto_connect_on_startup.toggled.connect(self.update_schedule_controls)
        self.hibernate_enabled.toggled.connect(self.update_schedule_controls)
        self.wake_time.timeChanged.connect(self.update_schedule_hint)
        self.sleep_time.timeChanged.connect(self.update_schedule_hint)
        self.edit_credentials_button.clicked.connect(self.toggle_credentials_editor)
        self.password_visibility_button.toggled.connect(self.update_password_visibility)
        self.stop_automation_button.clicked.connect(self.stop_automation)

        action_row = QHBoxLayout()
        action_row.setContentsMargins(0, 0, 0, 0)
        self.configure_button = QPushButton("保存并应用")
        self.configure_button.setObjectName("primaryButton")
        self.configure_button.setMinimumWidth(240)
        self.log_button = QPushButton("打开日志")
        self.log_button.setObjectName("linkButton")
        self.settings_status_label = QLabel("设置已保存")
        self.settings_status_label.setObjectName("settingsSaved")
        action_row.addWidget(self.settings_status_label)
        action_row.addStretch(1)
        action_row.addWidget(self.log_button)
        action_row.addWidget(self.configure_button)

        footer_row = QHBoxLayout()
        footer_row.setContentsMargins(0, 0, 0, 0)
        privacy_hint = QLabel("凭据保存在 Windows 凭据管理器，日志已脱敏。")
        privacy_hint.setObjectName("footerText")
        footer_row.addWidget(privacy_hint)
        footer_row.addStretch(1)
        version_label = QLabel(f"版本 {PRODUCT_VERSION}")
        version_label.setObjectName("footerText")
        footer_row.addWidget(version_label)

        self.footer_bar = QFrame()
        self.footer_bar.setObjectName("footerBar")
        footer_layout = QVBoxLayout(self.footer_bar)
        footer_layout.setContentsMargins(20, 10, 20, 9)
        footer_layout.setSpacing(4)
        footer_layout.addLayout(action_row)
        footer_layout.addLayout(footer_row)
        root_layout.addWidget(self.footer_bar)

        self.configure_button.clicked.connect(self.configure_and_install)
        self.reauthenticate_button.clicked.connect(self.run_network_logout)
        self.login_validate_button.clicked.connect(self.run_login_validation)
        self.dorm_script_survey_button.clicked.connect(self.run_dorm_script_survey)
        self.network_details_button.clicked.connect(self.show_network_details)
        self.log_button.clicked.connect(self.open_logs)
        for signal in (
            self.auto_connect_on_startup.toggled,
            self.wake_enabled.toggled,
            self.hibernate_enabled.toggled,
            self.start_uu.toggled,
            self.keep_login_page_open.toggled,
            self.wireless_http_experimental.toggled,
            self.dorm_protocol_observer_enabled.toggled,
            self.ruijie_background_client_fallback.toggled,
            self.connection_mode.currentIndexChanged,
            self.operator.currentIndexChanged,
            self.ruijie_path.textChanged,
            self.uu_path.textChanged,
            self.username.textChanged,
            self.password.textChanged,
            self.wake_time.timeChanged,
            self.sleep_time.timeChanged,
        ):
            signal.connect(self._mark_settings_dirty)
        self.ruijie_background_client_fallback.toggled.connect(
            self._on_fallback_toggled)
        self.connection_mode.currentIndexChanged.connect(self.on_connection_mode_changed)
        self._apply_styles()
        self.update_uu_controls()
        self.update_connection_mode_hint()
        self.update_credentials_hint()
        credentials_required = self.config.auth_paused or not self._credentials_available
        self._set_credentials_editor_visible(credentials_required)
        self.details_container.setVisible(True)
        self.update_schedule_controls()
        self._mark_settings_saved()

        from .ui_layout import rebuild
        rebuild(self)

        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        menu = QMenu(self)
        show_action = QAction("显示主界面", self)
        show_action.triggered.connect(self.showNormal)
        stop_and_exit_action = QAction("停止自动化并退出", self)
        stop_and_exit_action.triggered.connect(self.stop_automation_and_exit)
        exit_action = QAction("退出界面（自动化继续）", self)
        exit_action.triggered.connect(self.exit_app)
        menu.addAction(show_action)
        menu.addSeparator()
        menu.addAction(stop_and_exit_action)
        menu.addAction(exit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.handle_tray_activation)
        self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1500)
        self.refresh()

    @Slot(QSystemTrayIcon.ActivationReason)
    def handle_tray_activation(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Open only for a left activation; right-click must only show the menu."""
        if reason in {
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        }:
            self.showNormal()
            self.activateWindow()

    def _make_card(self, title: str | None = None) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 15, 18, 15)
        card_layout.setSpacing(10)
        if title:
            card_layout.addWidget(self._section_title(title))
        return card, card_layout

    @staticmethod
    def _section_title(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("sectionTitle")
        return label

    @staticmethod
    def _make_time_adjuster(
        value: str,
        accessible_name: str,
    ) -> tuple[QWidget, QTimeEdit, QToolButton, QToolButton]:
        editor = QTimeEdit(QTime.fromString(value, "HH:mm"))
        editor.setDisplayFormat("HH:mm")
        editor.setAlignment(Qt.AlignCenter)
        editor.setButtonSymbols(QAbstractSpinBox.NoButtons)
        editor.setFixedWidth(78)
        editor.setAccessibleName(accessible_name)

        up_button = QToolButton()
        up_button.setObjectName("timeStepButton")
        up_button.setArrowType(Qt.UpArrow)
        up_button.setToolTip(f"增加{accessible_name}")
        up_button.setAccessibleName(f"增加{accessible_name}")
        up_button.setFocusPolicy(Qt.NoFocus)
        up_button.setAutoRepeat(True)
        up_button.setMinimumSize(30, 17)

        down_button = QToolButton()
        down_button.setObjectName("timeStepButton")
        down_button.setArrowType(Qt.DownArrow)
        down_button.setToolTip(f"减少{accessible_name}")
        down_button.setAccessibleName(f"减少{accessible_name}")
        down_button.setFocusPolicy(Qt.NoFocus)
        down_button.setAutoRepeat(True)
        down_button.setMinimumSize(30, 17)

        up_button.clicked.connect(lambda _checked=False: editor.stepUp())
        down_button.clicked.connect(lambda _checked=False: editor.stepDown())

        button_column = QVBoxLayout()
        button_column.setContentsMargins(0, 0, 0, 0)
        button_column.setSpacing(2)
        button_column.addWidget(up_button)
        button_column.addWidget(down_button)

        control = QWidget()
        control_layout = QHBoxLayout(control)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(4)
        control_layout.addWidget(editor)
        control_layout.addLayout(button_column)
        return control, editor, up_button, down_button

    def _apply_styles(self) -> None:
        from .ui_layout import STYLE
        self.setStyleSheet(STYLE)

    def _mark_settings_dirty(self, *_args) -> None:
        self._settings_dirty = True
        self.settings_status_label.setText("有未应用的修改（所有标签页）")
        self.settings_status_label.setStyleSheet("color: #9a4b00; font-weight: 600;")
        if hasattr(self, "tabs"):
            source = self.sender()
            for index, (page, title) in enumerate(((self.connection_page, "连接"), (self.automation_page, "自动化"))):
                if isinstance(source, QWidget) and page.isAncestorOf(source):
                    self.tabs.setTabText(index, title + " ·")

    def _mark_settings_saved(self) -> None:
        self._settings_dirty = False
        self.settings_status_label.setText("设置已保存")
        self.settings_status_label.setStyleSheet("color: #176b3a; font-weight: 600;")
        if hasattr(self, "tabs"):
            for index, title in enumerate(("连接", "自动化", "维护")):
                self.tabs.setTabText(index, title)

    def refresh(self) -> None:
        status = read_status()
        self._last_status = status
        self.status_label.setText(str(status.get("message") or "尚未运行"))
        self._update_status_badge(status)
        self.update_native_validation_labels()
        stage = str(status.get("stage") or "")
        if stage in {"authentication-paused", "portal-allowlist-blocked"}:
            alert_time = str(status.get("time") or stage)
            if alert_time != self._last_auth_alert_time:
                self._last_auth_alert_time = alert_time
                self.config = load_config()
                self.update_credentials_hint()
                if stage == "portal-allowlist-blocked":
                    QMessageBox.warning(
                        self,
                        "官方门户校验未通过",
                        "认证页面没有通过官方门户允许列表校验，程序没有填写或提交账号密码。"
                        "后台认证已经暂停，不会反复打开页面。",
                    )
                else:
                    self._set_credentials_editor_visible(True)
                    reason = str(status.get("reason") or self.config.auth_pause_reason or "")
                    reason_messages = {
                        "account-invalid": "校园网门户提示账号错误或账号不存在。",
                        "password-invalid": "校园网门户提示密码错误。",
                        "credentials-invalid": "校园网门户提示账号或密码错误。",
                        "operator-invalid": "程序未能匹配所选运营商。",
                        "submission-rate-limit": "15 分钟内账号密码提交次数已达到上限。",
                        "result-unknown": "账号密码已提交一次，但认证结果无法确认。",
                    }
                    QMessageBox.warning(
                        self,
                        "校园网认证已暂停",
                        reason_messages.get(reason, "门户明确拒绝了本次认证。")
                        + "为避免重复提交，后台自动登录已暂停。\n\n"
                        + "请重新输入账号、密码并确认运营商，然后点击“保存并应用”。",
                    )
        # 任务查询会调用 schtasks.exe；无需每次 1.5 秒的界面刷新都启动外部进程。
        self._task_refresh_counter += 1
        if self._task_refresh_counter == 1 or self._task_refresh_counter % 7 == 0:
            self._task_names = installed_task_names()
        names = self._task_names
        if names:
            self.task_label.setText("自动化任务：正常")
        elif is_admin():
            self.task_label.setText("自动化任务：尚未安装")
        else:
            self.task_label.setText("自动化任务：首次保存时需要管理员授权")
        self._update_monitor_label(status, names)
        self.update_next_action()
        self._update_network_actions(status)
        applied_mode = status.get("connection_mode") or self.config.connection_mode
        self.status_title.setText({
            CONNECTION_MODE_WIRELESS: "全校无线网",
            CONNECTION_MODE_DORM_ETHERNET: "宿舍有线网",
            CONNECTION_MODE_WORKSTATION_RUIJIE: "工位有线网",
        }.get(applied_mode, "校园网连接"))
        if hasattr(self, "maintenance_status"):
            timestamp = str(status.get("time") or "尚无时间记录")
            self.maintenance_status.setText(
                f"{self.status_badge.text()} · {self.status_label.text()}\n最近状态时间：{timestamp}"
            )

    def _update_network_actions(self, status: dict) -> None:
        if self._manual_action_is_running() or self._verify_thread_running():
            self.native_verify_button.setEnabled(False)
            self.reauthenticate_button.setEnabled(False)
            self.login_validate_button.setEnabled(False)
            self.dorm_script_survey_button.setEnabled(False)
            if self._verify_thread_running():
                workstation = (
                    self.connection_mode.currentData()
                    == CONNECTION_MODE_WORKSTATION_RUIJIE
                )
                self.native_verify_button.setVisible(workstation)
                self.native_verify_hint.setText("正在检查并验证…")
                self.native_verify_hint.setVisible(workstation)
            return
        badge = self.status_badge.text()
        online = status.get("current_online") is True or badge == "已联网"
        offline = status.get("current_online") is False or badge == "未联网"
        verify_required = self._native_verification_required()
        self.native_verify_button.setVisible(verify_required)
        self.native_verify_hint.setVisible(verify_required)
        if verify_required:
            self.native_verify_hint.setText(self._native_verify_hint_text(online))
            self.login_validate_button.setVisible(False)
            # 在线时保留注销入口；状态未知或离线时不显示注销。
            self.reauthenticate_button.setVisible(online)
        else:
            self.reauthenticate_button.setVisible(not offline)
            self.login_validate_button.setVisible(not online)
        self.native_verify_button.setEnabled(True)
        self.reauthenticate_button.setEnabled(True)
        self.login_validate_button.setEnabled(True)
        self.dorm_script_survey_button.setEnabled(True)

    def _update_status_badge(self, status: dict) -> None:
        stage = str(status.get("stage") or "not-started").lower()
        success = status.get("success")
        if stage in {"authentication-paused", "portal-allowlist-blocked"}:
            text, foreground, background = "需要处理", "#9b1c1c", "#fde8e8"
        elif stage in {"monitor-passive-waiting", "waiting-for-campus-wifi"}:
            text, foreground, background = "等待联网", "#8a4b08", "#fff3d6"
        elif any(marker in stage for marker in ("recover", "login", "connect", "logout", "probe")) and not any(
            marker in stage for marker in ("failed", "offline")
        ):
            text, foreground, background = "正在处理", "#1d4f91", "#e8f1ff"
        elif success is True and any(
            marker in stage for marker in ("online", "succeeded", "confirmed", "already")
        ):
            text, foreground, background = "已联网", "#176b3a", "#e4f5ea"
        elif any(marker in stage for marker in ("failed", "offline", "unavailable")):
            text, foreground, background = "未联网", "#9b1c1c", "#fde8e8"
        elif stage in {"not-started", "unknown"}:
            text, foreground, background = "尚未运行", "#5f6b7a", "#eef1f4"
        elif success is True:
            text, foreground, background = "运行正常", "#176b3a", "#e4f5ea"
        else:
            text, foreground, background = "状态更新", "#5f6b7a", "#eef1f4"
        self.status_badge.setText(text)
        self.status_badge.setStyleSheet(
            f"color: {foreground}; background: {background}; "
            "border-radius: 10px; padding: 4px 10px; font-weight: 600;"
        )

    def _update_monitor_label(self, status: dict, task_names: list[str]) -> None:
        stage = str(status.get("stage") or "").lower()
        policy = str(status.get("monitor_policy") or "").lower()
        if stage in {"authentication-paused", "portal-allowlist-blocked"}:
            text = "监测：认证提交已暂停"
        elif policy == "passive" or stage == "monitor-passive-waiting":
            text = "监测：等待首次联网"
        elif policy == "active" or stage == "online":
            text = "监测：主动监测中"
        elif any(name.endswith("-Monitor") for name in task_names):
            text = "监测：后台任务已准备"
        else:
            text = "监测：尚未安装"
        self.monitor_label.setText(text)

    def update_next_action(self) -> None:
        now = datetime.now()
        candidates: list[tuple[datetime, str]] = []
        if self.config.wake_enabled:
            candidates.append((self._next_occurrence(now, QTime.fromString(self.config.wake_time, "HH:mm")), "唤醒并联网"))
        if self.config.hibernate_enabled:
            candidates.append((self._next_occurrence(now, QTime.fromString(self.config.sleep_time, "HH:mm")), "自动休眠"))
        if not candidates:
            self.next_action_label.setText("下一步：保持后台联网监测")
            return
        when, action = min(candidates, key=lambda item: item[0])
        day = "今天" if when.date() == now.date() else "明天"
        self.next_action_label.setText(f"下一步：{day} {when:%H:%M} {action}")

    @staticmethod
    def _next_occurrence(now: datetime, value: QTime) -> datetime:
        target = now.replace(hour=value.hour(), minute=value.minute(), second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return target

    @Slot(bool)
    def update_uu_controls(self, _checked: bool | None = None) -> None:
        enabled = self.start_uu.isChecked()
        self.uu_path.setEnabled(enabled)
        self.uu_browse_button.setEnabled(enabled)
        self.uu_path_label.setVisible(enabled)
        self.uu_path_row.setVisible(enabled)

    @Slot()
    def update_connection_mode_hint(self) -> None:
        selected_mode = self.connection_mode.currentData()
        workstation_mode = selected_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
        if selected_mode == CONNECTION_MODE_DORM_ETHERNET:
            text = "仅用于宿舍网口的网页登录认证。"
        elif workstation_mode:
            text = "南医工位有线网：程序直接完成认证与保活，无需安装锐捷客户端。"
        else:
            text = "仅针对NJMU_WLAN"
        self.connection_mode_hint.setText(text)
        self.ruijie_path_label.setVisible(False)
        self.ruijie_path_row.setVisible(False)
        self.native_fallback_row.setVisible(workstation_mode)
        self.rawether_check_button.setVisible(
            workstation_mode and self.ruijie_background_client_fallback.isChecked()
        )
        self.rawether_check_status.setVisible(
            workstation_mode and self.ruijie_background_client_fallback.isChecked()
        )
        self.ruijie_background_client_fallback.setVisible(workstation_mode)
        self.operator_label.setVisible(not workstation_mode)
        self.operator.setVisible(not workstation_mode)
        self.keep_login_page_open.setVisible(not workstation_mode)
        self.wireless_http_experimental.hide()
        self.dorm_protocol_observer_enabled.hide()
        self.dorm_script_survey_button.hide()
        if hasattr(self, "wireless_strategy"):
            self.wireless_strategy.setVisible(selected_mode == CONNECTION_MODE_WIRELESS)
        if hasattr(self, "connection_form"):
            from .ui_layout import sync_rows
            sync_rows(self)
        self._update_network_actions(self._last_status)

    @Slot()
    def _prompt_npcap_install(self) -> bool:
        """工位有线需要 Npcap：让用户选择随程序提供的安装包并提权运行。"""
        program_dir = Path(sys.executable).resolve().parent
        tools_dir = program_dir / "tools"
        while not npcap_detected():
            box = QMessageBox(self)
            box.setWindowTitle("需要安装 Npcap")
            box.setIcon(QMessageBox.Warning)
            box.setText("工位有线网需要先安装 Npcap 才能使用。")
            box.setInformativeText(
                "请选择随程序一起提供的 Npcap 安装包（npcap-x.yy.exe）。\n"
                "程序会以管理员权限运行它；安装完成后回到本窗口点“重新检测”。")
            choose = box.addButton("选择安装包…", QMessageBox.AcceptRole)
            recheck = box.addButton("重新检测", QMessageBox.ActionRole)
            box.addButton("取消", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() is choose:
                start_dir = str(tools_dir if tools_dir.is_dir() else program_dir)
                selected, _ = QFileDialog.getOpenFileName(
                    self, "选择 Npcap 安装包", start_dir,
                    "Npcap 安装包 (npcap-*.exe);;可执行程序 (*.exe)")
                if selected:
                    self._run_installer_elevated(selected)
                    QMessageBox.information(
                        self, "安装 Npcap",
                        "安装完成后回到本窗口点“重新检测”。")
                continue
            if box.clickedButton() is recheck:
                continue
            return False
        return True

    def _run_installer_elevated(self, path: str) -> bool:
        try:
            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", path, None, None, 1)
            return int(result) > 32
        except Exception:
            return False
    def _ensure_npcap_for_workstation(self) -> bool:
        if npcap_detected():
            return True
        return self._prompt_npcap_install()

    @Slot(int)
    def on_connection_mode_changed(self, _index: int) -> None:
        previous = getattr(self, "_last_connection_mode_index", 0)
        if (self.connection_mode.currentData() == CONNECTION_MODE_WORKSTATION_RUIJIE
                and not self._ensure_npcap_for_workstation()):
            self.connection_mode.setCurrentIndex(previous)
            return
        self._last_connection_mode_index = self.connection_mode.currentIndex()
        self.update_connection_mode_hint()

    @Slot(bool)
    def _on_fallback_toggled(self, _checked: bool = False) -> None:
        self.update_connection_mode_hint()
        self.update_native_validation_labels()
        self._mark_settings_dirty()

    def _verify_thread_running(self) -> bool:
        if self.verify_thread is None:
            return False
        try:
            return self.verify_thread.isRunning()
        except RuntimeError:
            self.verify_thread = None
            self.verify_worker = None
            return False

    def _native_verification_required(self) -> bool:
        """Show the one-time setup action whenever the native gate is invalid."""
        if self.connection_mode.currentData() != CONNECTION_MODE_WORKSTATION_RUIJIE:
            return False
        if not self.config.ruijie_native_auto_enabled:
            return True
        return not primary_status()["valid"]

    def _native_verify_hint_text(self, online: bool) -> str:
        if online:
            return "当前已联网。请先点击“断开校园网认证”，再完成原生认证检查验证。"
        reason = primary_status()["reason"] if self.config.ruijie_native_auto_enabled else "never-verified"
        messages = {
            "never-verified": "首次使用工位有线网：请先断开校园网认证，再点击“原生认证检查并验证”。",
            "app-version-changed": "程序已更新，需要重新进行原生认证验证。请先断开校园网认证后再验证。",
            "bridge-changed": "Npcap 组件已更新，需要重新进行原生认证验证。请先断开校园网认证后再验证。",
            "bridge-missing": "未找到可用的 Npcap 组件，请重新安装或修复程序后再验证。",
            "backend-mismatch": "验证记录与当前 Npcap 认证方式不一致，需要重新验证。",
        }
        return messages.get(reason, "需要完成原生认证验证后才能启用后台自动认证。")

    def update_native_validation_labels(self) -> None:
        if self.ruijie_background_client_fallback.isChecked():
            fallback = fallback_status(self.ruijie_path.text().strip())
            self.rawether_check_status.setText(
                "已通过" if (self.ruijie_path.text().strip() and fallback["valid"]) else "未检查"
            )
        else:
            self.rawether_check_status.setText("未启用")

    @Slot()
    def run_native_verification(self) -> None:
        if self._manual_action_is_running() or self._verify_thread_running():
            return
        if self.connection_mode.currentData() != CONNECTION_MODE_WORKSTATION_RUIJIE:
            QMessageBox.information(self, "模式不符", "请先选择“工位有线网”。")
            return
        if self.connection_mode.currentData() != self.config.connection_mode:
            QMessageBox.information(
                self,
                "请先保存设置",
                "当前选择的连接方式尚未应用。请先点击“保存并应用”，再完成原生认证验证。",
            )
            return
        self.config = load_config()
        self.native_verify_button.setEnabled(False)
        self.native_verify_hint.setText("正在检查并验证…")
        self.native_verify_hint.setVisible(True)
        self.verify_thread = QThread(self)
        self.verify_worker = NativeVerifyWorker(self.config)
        self.verify_worker.moveToThread(self.verify_thread)
        self.verify_thread.started.connect(self.verify_worker.run)
        self.verify_worker.finished.connect(self._native_verify_finished)
        self.verify_worker.finished.connect(self.verify_thread.quit)
        self.verify_worker.finished.connect(self.verify_worker.deleteLater)
        self.verify_thread.finished.connect(self._native_verify_thread_finished)
        self.verify_thread.finished.connect(self.verify_thread.deleteLater)
        self.verify_thread.start()

    @Slot(dict)
    def _native_verify_finished(self, result: dict) -> None:
        self.config = load_config()
        if result.get("success"):
            event("native-verification-ui", True, "原生认证检查验证成功")
            QMessageBox.information(
                self,
                "原生认证验证成功",
                "原生认证检查已通过，后台自动认证已启用。\n\n"
                "以后离线时可直接点击“立即认证并检查联网”；"
                "程序或 Npcap 组件更新后会再次要求验证。",
            )
        else:
            message = str(result.get("message") or "验证未成功")
            event("native-verification-ui", False, message)
            QMessageBox.warning(
                self,
                "原生认证检查验证失败",
                message + "\n\n请按提示处理后重新点击“原生认证检查并验证”。",
            )

    @Slot()
    def _native_verify_thread_finished(self) -> None:
        self.verify_thread = None
        self.verify_worker = None
        self.native_verify_button.setEnabled(True)
        self.refresh()

    @Slot()
    def open_rawether_check(self) -> None:
        if self._manual_action_is_running():
            return
        from .native_wired_gui import RawetherFallbackDialog
        dialog = RawetherFallbackDialog(self, self.ruijie_path.text().strip())
        dialog.exec()
        checked_path = dialog.checked_client_path or dialog.client_path.text().strip()
        if checked_path and checked_path != self.ruijie_path.text().strip():
            self.ruijie_path.setText(checked_path)
            self._mark_settings_dirty()
        self.update_native_validation_labels()

    @Slot()
    def select_ruijie_path(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "选择官方锐捷客户端",
            self.ruijie_path.text().strip(),
            "锐捷客户端 (RuijieSupplicant.exe 8021x.exe);;可执行程序 (*.exe)",
        )
        if selected:
            self.ruijie_path.setText(selected)

    @Slot()
    def select_uu_path(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self,
            "选择 UU 远程运行文件",
            self.uu_path.text().strip(),
            "可执行程序 (*.exe);;所有文件 (*)",
        )
        if selected:
            self.uu_path.setText(selected)

    @Slot()
    def update_schedule_hint(self) -> None:
        wake = self.wake_time.time().toString("HH:mm")
        sleep = self.sleep_time.time().toString("HH:mm")
        wake_enabled = self.wake_enabled.isChecked()
        hibernate_enabled = self.hibernate_enabled.isChecked()
        parts = [
            "开机后自动联网" if self.auto_connect_on_startup.isChecked() else "开机后等待首次联网",
            f"每天 {wake} 唤醒" if wake_enabled else "不定时唤醒",
            "联网后启动 UU" if self.start_uu.isChecked() else "不自动启动 UU",
            f"每天 {sleep} 休眠" if hibernate_enabled else "不自动休眠",
        ]
        self.schedule_hint.setText("当前设置：" + "；".join(parts) + "。")
        self.update_next_action()

    @Slot(bool)
    def update_schedule_controls(self, _checked: bool | None = None) -> None:
        wake_enabled = self.wake_enabled.isChecked()
        hibernate_enabled = self.hibernate_enabled.isChecked()
        self.wake_time_control.setEnabled(wake_enabled)
        self.wake_time_control.setVisible(wake_enabled)
        self.wake_disabled_label.setVisible(not wake_enabled)
        self.sleep_time_control.setEnabled(hibernate_enabled)
        self.sleep_time_control.setVisible(hibernate_enabled)
        self.sleep_disabled_label.setVisible(not hibernate_enabled)
        self.update_schedule_hint()

    def update_credentials_hint(self) -> None:
        try:
            load_credentials()
            available = True
        except Exception:
            available = False
        self._credentials_available = available
        if self.config.auth_paused:
            text = "认证已暂停，需要重新输入"
            color = "#9b1c1c"
        elif available:
            text = "已安全保存"
            color = "#176b3a"
        else:
            text = "尚未配置"
            color = "#9b5b00"
        self.credentials_hint.setText(text)
        self.credentials_hint.setStyleSheet(f"color: {color};")

    @Slot()
    def toggle_credentials_editor(self) -> None:
        self._set_credentials_editor_visible(self.credentials_editor.isHidden())

    def _set_credentials_editor_visible(self, visible: bool) -> None:
        if not visible:
            self.password_visibility_button.setChecked(False)
        if visible and hasattr(self, "tabs"):
            self.tabs.setCurrentIndex(0)
        self.credentials_editor.setVisible(visible)
        if hasattr(self, "connection_form"):
            from .ui_layout import sync_rows
            sync_rows(self)
        self.edit_credentials_button.setText("收起账号输入" if visible else "更换账号或密码")

    @Slot(bool)
    def update_password_visibility(self, visible: bool) -> None:
        self.password.setEchoMode(QLineEdit.Normal if visible else QLineEdit.Password)
        self.password_visibility_button.setIcon(_password_eye_icon(not visible))
        label = "隐藏密码" if visible else "显示密码"
        self.password_visibility_button.setToolTip(label)
        self.password_visibility_button.setAccessibleName(label)

    @Slot()
    def stop_automation(self) -> None:
        answer = QMessageBox.question(
            self,
            "停止自动化",
            (
                "这会立即停止后台联网监测，并删除本程序创建的唤醒登录、休眠和监测计划任务。\n\n"
                "账号、配置、日志和程序文件会保留，以后点击“保存并应用”即可重新启用。是否继续？"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        if self._remove_automation_tasks():
            QMessageBox.information(
                self,
                "已停止",
                "后台监测已停止，全部自动化计划任务已清理。\n\n现在可以退出程序，然后删除整个便携文件夹。",
            )
        self.refresh()

    def _remove_automation_tasks(self) -> bool:
        try:
            from .rawether import stop_private_session
            session_stopped = stop_private_session("stop-automation")
            remove_all_tasks_with_elevation()
            if not session_stopped:
                raise RuntimeError("自动化任务已清理，但后台原生锐捷保活未能停止")
            return True
        except Exception as error:
            event("gui-stop-automation", False, f"{type(error).__name__}: {error}")
            QMessageBox.critical(self, "停止失败", f"自动化任务未能全部清理：\n{error}")
            return False

    @Slot()
    def stop_automation_and_exit(self) -> None:
        answer = QMessageBox.question(
            self,
            "停止自动化并退出",
            (
                "这会结束后台联网监测，删除本程序创建的全部计划任务，然后退出界面。\n\n"
                "账号、配置和日志仍会保留。退出后即可删除整个便携文件夹。是否继续？"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes or not self._remove_automation_tasks():
            return
        self._allow_close = True
        self.tray.hide()
        QApplication.quit()

    def _apply_fallback_preference(self, config, ruijie_path: str, *, warn: bool) -> bool:
        """Persist the fallback checkbox only when its read-only check is valid."""
        if not self.ruijie_background_client_fallback.isChecked():
            config.rawether_fallback_enabled = False
            return False
        if not ruijie_path:
            config.rawether_fallback_enabled = False
            if warn:
                QMessageBox.warning(
                    self,
                    "后备连接未启用",
                    "已勾选“锐捷驱动作为后备连接”，但尚未在“锐捷驱动检查”中选择客户端并通过检查。\n\n"
                    "本次保存不会启用后备连接；Npcap 原生认证设置不受影响。",
                )
            self.ruijie_background_client_fallback.setChecked(False)
            return False
        if fallback_status(ruijie_path)["valid"]:
            config.rawether_fallback_enabled = True
            return True
        config.rawether_fallback_enabled = False
        if warn:
            QMessageBox.warning(
                self,
                "后备连接未启用",
                "已勾选“锐捷驱动作为后备连接”，但尚未通过“锐捷驱动检查”。\n\n"
                "本次保存不会启用后备连接；Npcap 原生认证设置不受影响。",
            )
        self.ruijie_background_client_fallback.setChecked(False)
        return False

    def configure_and_install(self) -> None:
        username = self.username.text().strip()
        password = self.password.text()
        entering_credentials = bool(username or password)
        if entering_credentials and (not username or not password):
            QMessageBox.warning(self, "凭据不完整", "账号和密码必须同时填写；如仅修改时间，请将两项都留空。")
            return
        uu_path = self.uu_path.text().strip()
        if self.start_uu.isChecked() and not uu_path:
            QMessageBox.warning(self, "UU 路径为空", "已选择联网后启动 UU 远程，请先选择 UU 远程运行文件。")
            return
        manual_pause_remaining = 0
        pause_state = load_monitor_state(self.config)
        if (
            str(pause_state.get("monitor_suppression_source") or "")
            == "manual-network-logout"
        ):
            manual_pause_remaining = suppression_remaining_seconds(pause_state)
        if manual_pause_remaining > 0:
            remaining_minutes = max(1, (manual_pause_remaining + 59) // 60)
            if self.auto_connect_on_startup.isChecked():
                resume_hint = (
                    "保存成功后会取消暂停，后台监测将恢复；"
                    "由于已开启“开机后自动联网”，可能会立即重新认证。"
                )
            else:
                resume_hint = (
                    "保存成功后会取消暂停；当前未开启“开机后自动联网”，"
                    "后台只恢复被动监测，不会主动重新认证。"
                )
            if QMessageBox.question(
                self,
                "取消注销后的暂停？",
                f"当前处于手动注销后的暂停期，剩余约 {remaining_minutes} 分钟。\n\n"
                f"{resume_hint}\n\n是否继续保存并应用？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            ) != QMessageBox.Yes:
                return
        selected_connection_mode = str(
            self.connection_mode.currentData() or CONNECTION_MODE_WIRELESS
        )
        ruijie_path = self.ruijie_path.text().strip() or self.config.ruijie_path
        if (selected_connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                and not npcap_detected()):
            if not self._prompt_npcap_install():
                return
        if not entering_credentials:
            try:
                load_credentials()
            except Exception:
                QMessageBox.warning(self, "缺少凭据", "尚未保存校园网凭据，请输入账号和密码。")
                return
            if (
                self.config.auth_paused
                and self.config.auth_pause_reason != "portal-allowlist-blocked"
            ):
                QMessageBox.warning(self, "需要新凭据", "认证已暂停，请重新输入账号和密码后再保存。")
                return
        try:
            previous_connection_mode = self.config.connection_mode
            self.config.connection_mode = selected_connection_mode
            self.config.ruijie_path = ruijie_path
            self._apply_fallback_preference(self.config, ruijie_path, warn=True)
            if (
                previous_connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                and selected_connection_mode != CONNECTION_MODE_WORKSTATION_RUIJIE
            ):
                from .rawether import stop_private_session
                if not stop_private_session("settings-change"):
                    raise RuntimeError("旧的后台原生锐捷保活未能停止，设置尚未保存")
            self.config.portal.operator = self.operator.currentText()
            self.config.wake_enabled = self.wake_enabled.isChecked()
            self.config.auto_connect_on_startup = self.auto_connect_on_startup.isChecked()
            self.config.hibernate_enabled = self.hibernate_enabled.isChecked()
            self.config.wake_time = self.wake_time.time().toString("HH:mm")
            self.config.sleep_time = self.sleep_time.time().toString("HH:mm")
            self.config.start_uu = self.start_uu.isChecked()
            self.config.uu_path = uu_path
            self.config.keep_login_page_open = self.keep_login_page_open.isChecked()
            self.config.wireless_http_experimental = True
            self.config.dorm_protocol_observer_enabled = False
            if self.config.auth_pause_reason == "portal-allowlist-blocked":
                self.config.auth_paused = False
                self.config.auth_pause_reason = ""
                self.config.auth_paused_at = ""
                self.config.portal_allowlist_manual_retry_available = True
            apply_schedule(self.config)
            if entering_credentials:
                save_credentials(username, password)
                self.config.auth_paused = False
                self.config.auth_pause_reason = ""
                self.config.auth_paused_at = ""
                self.config.login_submission_timestamps = []
                self.config.ruijie_submission_timestamps = []
                self.config.portal_allowlist_manual_retry_available = True
            save_config(self.config)
            result = install_with_elevation(self.config)
            cleared_manual_pause = False
            pause_clear_error = ""
            if manual_pause_remaining > 0:
                try:
                    clear_monitor_suppression(self.config, "settings-saved")
                    cleared_manual_pause = True
                    event(
                        "manual-logout-pause-cancelled",
                        True,
                        "保存并应用后已取消手动注销的 5 分钟暂停",
                    )
                except Exception as error:
                    pause_clear_error = f"{type(error).__name__}: {error}"
                    event(
                        "manual-logout-pause-cancel-failed",
                        False,
                        "保存成功，但未能取消手动注销暂停",
                        reason=pause_clear_error,
                    )
            event("gui-configure", True, "设置已保存并完成计划任务更新", installed_tasks=result.get("installed", []))
            pause_result = ""
            if cleared_manual_pause:
                pause_result = "\n\n已取消手动注销后的暂停，后台监测将按当前设置恢复。"
            elif pause_clear_error:
                pause_result = (
                    "\n\n注意：保存已成功，但未能清除注销后的暂停。"
                    f"\n原因：{pause_clear_error}"
                )
            QMessageBox.information(
                self,
                "配置完成",
                "凭据与功能开关已保存，计划任务已按选择更新。"
                f"{pause_result}\n\n"
                f"连接方式：{self.connection_mode.currentText()}\n"
                f"每天定时唤醒：{'开启（' + self.config.wake_time + '）' if self.config.wake_enabled else '关闭'}\n"
                f"每天定时休眠：{'开启（' + self.config.sleep_time + '）' if self.config.hibernate_enabled else '关闭'}\n"
                f"开机后自动联网：{'开启' if self.config.auto_connect_on_startup else '关闭（等待首次联网或定时唤醒）'}\n"
                f"联网后启动 UU：{'是' if self.config.start_uu else '否'}",
            )
            self.username.clear()
            self.password.clear()
            self.update_credentials_hint()
            self._set_credentials_editor_visible(False)
            self._mark_settings_saved()
        except PermissionError as error:
            event("gui-configure", False, "计划任务安装需要管理员权限")
            QMessageBox.warning(self, "需要管理员权限", str(error) + "\n请右键使用“以管理员身份运行”重新打开程序。")
        except Exception as error:
            event("gui-configure", False, f"{type(error).__name__}: {error}")
            QMessageBox.critical(
                self,
                "配置失败",
                f"配置或计划任务安装失败：\n{error}\n\n详细信息已写入后台日志。",
            )
        self.refresh()

    def _prepare_manual_validation(self) -> bool:
        username = self.username.text().strip()
        password = self.password.text()
        entering_credentials = bool(username or password)
        if entering_credentials and (not username or not password):
            QMessageBox.warning(self, "凭据不完整", "账号和密码必须同时填写。")
            return False
        self.config = load_config()
        if not entering_credentials:
            try:
                load_credentials()
            except Exception:
                QMessageBox.warning(self, "缺少凭据", "请先输入校园网账号和密码。")
                return False
            allowlist_retry = (
                self.config.auth_pause_reason == "portal-allowlist-blocked"
                and self.config.portal_allowlist_manual_retry_available
            )
            if self.config.auth_paused and not allowlist_retry:
                QMessageBox.warning(
                    self,
                    "需要更正凭据",
                    "上一次认证已暂停。请重新输入账号和密码，并确认运营商后再验证。",
                )
                self._set_credentials_editor_visible(True)
                return False
        selected_connection_mode = str(
            self.connection_mode.currentData() or CONNECTION_MODE_WIRELESS
        )
        ruijie_path = self.ruijie_path.text().strip() or self.config.ruijie_path
        if (selected_connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                and not npcap_detected()):
            if not self._prompt_npcap_install():
                return False
        self.config.connection_mode = selected_connection_mode
        self.config.ruijie_path = ruijie_path
        self._apply_fallback_preference(self.config, ruijie_path, warn=True)
        self.config.portal.operator = self.operator.currentText()
        self.config.keep_login_page_open = self.keep_login_page_open.isChecked()
        self.config.wireless_http_experimental = True
        self.config.dorm_protocol_observer_enabled = False
        if entering_credentials:
            save_credentials(username, password)
            self.config.auth_paused = False
            self.config.auth_pause_reason = ""
            self.config.auth_paused_at = ""
            self.config.login_submission_timestamps = []
            self.config.ruijie_submission_timestamps = []
            self.config.portal_allowlist_manual_retry_available = True
            self.username.clear()
            self.password.clear()
        save_config(self.config)
        self.update_credentials_hint()
        return True

    def run_network_logout(self) -> None:
        self._run_manual_action("logout")

    def run_reauthentication(self) -> None:
        """Backward-compatible alias for the former first button handler."""
        self.run_network_logout()

    def run_login_validation(self) -> None:
        self._run_manual_action("validate_login")

    @Slot()
    def run_dorm_script_survey(self) -> None:
        if self._manual_action_is_running():
            return
        if self.connection_mode.currentData() != CONNECTION_MODE_DORM_ETHERNET:
            QMessageBox.warning(self, "模式不符", "请先选择“宿舍有线网”。")
            return
        answer = QMessageBox.question(
            self,
            "确认收集门户静态脚本",
            "本操作要求宿舍有线网当前已经联网。程序只会读取最近一次完整脱敏观察中出现过的官方静态 JavaScript，"
            "并绑定当前宿舍物理有线接口进行无 Cookie 的只读下载。\n\n"
            "不会注销、重新登录、提交账号密码或保存门户 HTML/API 响应。是否继续？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self.config = load_config()
        self.config.connection_mode = CONNECTION_MODE_DORM_ETHERNET
        self.manual_action = "dorm_static_script_survey"
        self.reauthenticate_button.setEnabled(False)
        self.login_validate_button.setEnabled(False)
        self.dorm_script_survey_button.setEnabled(False)
        self.status_label.setText("正在只读收集官方门户静态脚本；不会触发认证")
        self.login_thread = QThread(self)
        self.login_worker = LoginWorker(self.config, self.manual_action)
        self.login_worker.moveToThread(self.login_thread)
        self.login_thread.started.connect(self.login_worker.run)
        self.login_worker.finished.connect(self.login_finished)
        self.login_worker.finished.connect(self.login_thread.quit)
        self.login_worker.finished.connect(self.login_worker.deleteLater)
        self.login_thread.finished.connect(self._manual_action_thread_finished)
        self.login_thread.finished.connect(self.login_thread.deleteLater)
        self.login_thread.start()

    def run_login(self) -> None:
        """Backward-compatible alias for the first manual button."""
        self.run_network_logout()

    def _manual_action_is_running(self) -> bool:
        if self.login_thread is None:
            return False
        try:
            return self.login_thread.isRunning()
        except RuntimeError:
            # PySide raises when the C++ QThread has already been deleted but
            # a Python reference survived.  Recover instead of making every
            # later click appear to do nothing.
            self.login_thread = None
            self.login_worker = None
            return False

    def _start_logout_action(self) -> None:
        """注销只针对实际在用的网络：不保存草稿、不读凭据、不套用界面选择。"""
        from .controller import detect_active_connection
        self.config = load_config()
        try:
            detail = str(detect_active_connection(self.config).get("detail") or "")
        except Exception:
            detail = ""
        text = "将断开当前的校园网认证并确认已离线，随后暂停自动恢复 5 分钟。"
        if detail:
            text += "\n\n当前检测到：" + detail + "。"
        text += "\n\n随后 Windows 会请求一次管理员授权。是否继续？"
        if QMessageBox.question(
                self, "确认断开校园网认证", text,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No) != QMessageBox.Yes:
            return
        self.manual_action = "logout"
        self.reauthenticate_button.setEnabled(False)
        self.login_validate_button.setEnabled(False)
        self.status_label.setText("正在注销校园网络；确认离线后将暂停监测 5 分钟")
        self.login_thread = QThread(self)
        self.login_worker = LoginWorker(self.config, "logout")
        self.login_worker.moveToThread(self.login_thread)
        self.login_thread.started.connect(self.login_worker.run)
        self.login_worker.finished.connect(self.login_finished)
        self.login_worker.finished.connect(self.login_thread.quit)
        self.login_worker.finished.connect(self.login_worker.deleteLater)
        self.login_thread.finished.connect(self._manual_action_thread_finished)
        self.login_thread.finished.connect(self.login_thread.deleteLater)
        self.login_thread.start()

    def _run_manual_action(self, action: str) -> None:
        if self._manual_action_is_running():
            return
        logout_action = action == "logout"
        if logout_action:
            self._start_logout_action()
            return
        if (getattr(self, "connection_mode", None) is not None
                and self.connection_mode.currentData() != self.config.connection_mode):
            if QMessageBox.question(
                    self, "连接方式已更改但未保存",
                    "连接方式已更改但未保存，是否先保存并应用？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.Yes) != QMessageBox.Yes:
                return
            self.configure_and_install()
            self.config = load_config()
            if self.connection_mode.currentData() != self.config.connection_mode:
                return
        connection_mode_control = getattr(self, "connection_mode", None)
        workstation_mode = bool(
            connection_mode_control is not None
            and connection_mode_control.currentData() == CONNECTION_MODE_WORKSTATION_RUIJIE
        )
        confirmation_text = (
            (
                "此操作只适用于当前尚未通过工位有线认证的情况。程序将先用 Npcap 执行本程序原生认证，"
                "成功后启动每 30 秒一次的后台保活，并以真实联网探测判断结果；"
                "若已启用并通过检查的“锐捷驱动作为后备连接”，才会在 Npcap 失败后尝试 Rawether。\n\n"
                "只会进行一轮认证，不会无限重试。随后 Windows 会请求一次管理员授权。是否继续？"
            )
            if workstation_mode and not logout_action
            else (
                (
                    "程序会先停止本程序的后台保活，再向当前工位网卡发送 1 个标准 EAPOL-Logoff，"
                    "并以连续两次真实联网探测确认离线。确认成功后 5 分钟内暂停联网监测和自动恢复；"
                    "不会操作官方锐捷客户端的注销按钮。\n\n"
                    "随后 Windows 会请求一次管理员授权。是否继续？"
                    if workstation_mode else
                    "此操作只适用于当前已经联网的无线或宿舍有线网络。程序会注销现有认证并连续确认离线，"
                    "随后 5 分钟内暂停联网监测和自动恢复，不会自动重新登录。\n\n"
                    "随后 Windows 会请求一次管理员授权。是否继续？"
                )
                if logout_action
                else
                "此操作只适用于当前尚未通过校园网认证的情况，不会执行注销。程序只提交一次账号密码，"
                "并以真实联网探测判断是否成功。若当前已经联网，本次不会重复提交；需要下线时请使用“断开校园网认证”。\n\n"
                "若账号或密码错误，程序会明确提示并暂停继续提交。随后 Windows 会请求一次管理员授权。是否继续？"
            )
        )
        answer = QMessageBox.question(
            self,
            "确认断开校园网认证" if logout_action else "确认立即认证并检查联网",
            confirmation_text,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            if not self._prepare_manual_validation():
                return
        except Exception as error:
            event("manual-validation-prepare", False, f"{type(error).__name__}: {error}")
            QMessageBox.critical(self, "无法开始验证", f"保存本次验证设置失败：\n{error}")
            return
        self.manual_action = action
        self.reauthenticate_button.setEnabled(False)
        self.login_validate_button.setEnabled(False)
        self.status_label.setText(
            "正在注销校园网络；确认离线后将暂停监测 5 分钟"
            if logout_action
            else (
                (
                    "正在进行原生锐捷认证并启动后台保活"
                    if self.config.ruijie_native_auto_enabled
                    else "正在核对并操作官方锐捷客户端（只提交一次）"
                )
                if workstation_mode
                else "正在进行单次登录认证（不会注销）"
            )
        )
        self.login_thread = QThread(self)
        self.login_worker = LoginWorker(self.config, action)
        self.login_worker.moveToThread(self.login_thread)
        self.login_thread.started.connect(self.login_worker.run)
        self.login_worker.finished.connect(self.login_finished)
        self.login_worker.finished.connect(self.login_thread.quit)
        self.login_worker.finished.connect(self.login_worker.deleteLater)
        self.login_thread.finished.connect(self._manual_action_thread_finished)
        self.login_thread.finished.connect(self.login_thread.deleteLater)
        self.login_thread.start()

    @Slot()
    def _manual_action_thread_finished(self) -> None:
        self.login_thread = None
        self.login_worker = None
        if hasattr(self, "connection_mode"):
            self.update_connection_mode_hint()
        else:
            self.reauthenticate_button.setEnabled(True)
            self.login_validate_button.setEnabled(True)

    @Slot(bool)
    def login_finished(self, ok: bool) -> None:
        status = read_status()
        stage = str(status.get("stage") or "")
        reason = str(status.get("reason") or "")
        if self.manual_action == "dorm_static_script_survey":
            if ok:
                from .dorm_script_survey import SURVEY_DIR

                archive_file = str(status.get("archive_file") or "")
                QMessageBox.information(
                    self,
                    "收集完成",
                    "官方门户静态脚本调查包已生成。未执行登录或注销，也未发送 Cookie。\n\n"
                    f"文件：{SURVEY_DIR / archive_file}",
                )
            else:
                QMessageBox.warning(
                    self,
                    "未能收集",
                    str(status.get("message") or "静态脚本调查未完成；没有提交校园网凭据。"),
                )
            self.config = load_config()
            self.refresh()
            return
        reason_messages = {
            "account-invalid": "账号错误或账号不存在",
            "password-invalid": "密码错误",
            "credentials-invalid": "账号或密码错误",
            "operator-invalid": "运营商选择不正确",
            "submission-rate-limit": "15 分钟内提交次数已达到上限",
            "result-unknown": "账号密码已提交一次，但认证结果无法确认",
            "portal-allowlist-blocked": "认证页面未通过官方门户允许列表校验",
        }
        if ok:
            message = (
                "已成功注销校园网络并确认离线；未来 5 分钟内暂停联网监测和自动恢复。"
                if self.manual_action == "logout"
                else (
                    (
                        "原生锐捷认证成功，后台持续保活已启动，工位有线真实联网探测成功。"
                    )
                    if self.config.connection_mode == CONNECTION_MODE_WORKSTATION_RUIJIE
                    else "账号密码已提交一次，并通过真实联网探测，登录认证成功。"
                )
            )
            inline_survey_file = str(status.get("dorm_inline_survey_file") or "")
            if inline_survey_file:
                from .dorm_inline_survey import INLINE_SURVEY_DIR

                message += (
                    "\n\n内联包装器脱敏调查包已自动生成：\n"
                    f"{INLINE_SURVEY_DIR / inline_survey_file}"
                )
            QMessageBox.information(self, "操作成功", message)
        else:
            if stage == "manual-network-logout-requires-online":
                message = "当前没有在线认证可断开。需要联网时请使用“立即认证并检查联网”。"
            elif stage == "manual-login-validation-requires-offline":
                message = "当前已经联网，账号密码没有被重复提交。需要下线时请使用“断开校园网认证”。"
            elif stage == "authentication-paused":
                detail = reason_messages.get(reason, "校园网门户拒绝了本次认证")
                offline_note = "\n\n注销已经成功，当前电脑仍处于离线状态。" if status.get("logout_confirmed") and not status.get("current_online") else ""
                message = f"{detail}。程序不会继续自动重试，请更正后重新输入并验证。{offline_note}"
            elif stage == "portal-allowlist-blocked":
                message = (
                    "认证页面不在官方门户允许列表内，程序没有填写或提交账号密码。"
                    "后台认证已经暂停，不会反复打开页面。"
                )
                message += (
                    "您可以再次点击一次手动验证按钮，程序会重新执行完整允许列表校验。"
                    if status.get("manual_retry_available")
                    else "本次允许的人工复核已经用完，请检查设置后重新保存。"
                )
            elif stage == "workstation-logout-unavailable":
                message = "这是旧版本留下的状态；请重新点击“断开校园网认证”使用标准 EAPOL 注销。"
            elif stage in {
                "ruijie-ethernet-link-unavailable",
                "native-verification-required",
                "ruijie-submission-backoff",
            }:
                message = str(status.get("message") or "工位原生认证环境未通过检查，未提交账号密码。")
            else:
                message = str(status.get("message") or "本轮验证未成功，程序没有重复提交账号密码。")
            QMessageBox.warning(self, "验证未成功", message)
        self.config = load_config()
        if stage in {"authentication-paused", "portal-allowlist-blocked"}:
            self._last_auth_alert_time = str(status.get("time") or stage)
            if stage == "authentication-paused":
                self._set_credentials_editor_visible(True)
                self.update_credentials_hint()
        self.refresh()

    def show_usage(self) -> None:
        import os
        target = Path(sys.executable).parent / "使用说明.txt" if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2] / "使用说明.txt"
        try:
            os.startfile(str(target))
        except OSError:
            QMessageBox.information(self, "使用说明", f"说明文件：{target}")

    def open_logs(self) -> None:
        try:
            import os
            os.startfile(str(APP_DIR / "logs"))
        except OSError:
            QMessageBox.information(self, "日志目录", str(APP_DIR / "logs"))

    @Slot()
    def show_network_details(self) -> None:
        status = read_status()
        message = str(status.get("message") or self.status_label.text() or "尚未运行")
        QMessageBox.information(
            self,
            "联网详情",
            f"连接方式：{self.status_title.text()}\n"
            f"当前状态：{self.status_badge.text()}\n"
            f"状态说明：{message}\n"
            f"{self.monitor_label.text()}\n"
            f"{self.task_label.text()}\n"
            f"{self.next_action_label.text()}",
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._allow_close:
            self.tray.hide()
            event.accept()
        else:
            self.hide()
            self.tray.showMessage(PRODUCT_NAME, "程序已最小化到系统托盘，后台任务仍可继续运行。", QSystemTrayIcon.Information, 2500)
            event.ignore()

    def exit_app(self) -> None:
        self._allow_close = True
        self.close()


def run_gui() -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(PRODUCT_NAME)
    app.setApplicationVersion(PRODUCT_VERSION)
    app.setQuitOnLastWindowClosed(False)
    window = MainWindow()
    window.show()
    app.exec()


def smoke_check_gui_runtime() -> bool:
    """Load QtCore/QtGui/QtWidgets and create a real widget without user data."""
    from .native_wired_gui import RawetherFallbackDialog
    app = QApplication.instance() or QApplication([PRODUCT_NAME, "--gui-smoke-check"])
    probe = QWidget()
    probe.setWindowTitle(f"{PRODUCT_NAME} {PRODUCT_VERSION} GUI smoke check")
    probe.resize(320, 120)
    probe.show()
    app.processEvents()
    ready = probe.isVisible() and probe.size().width() == 320 and issubclass(RawetherFallbackDialog, QWidget)
    probe.close()
    app.processEvents()
    return ready
