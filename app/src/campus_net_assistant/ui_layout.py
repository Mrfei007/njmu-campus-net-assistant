"""Presentation only: arrange existing controls without replacing action handlers."""
from pathlib import Path

from PySide6.QtCore import Qt, Signal, QSize
from .ui_icons import icon
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QTabWidget,
    QScrollArea, QPushButton, QFormLayout, QToolButton, QMessageBox, QSizePolicy,
    QTabBar, QStackedWidget,
)

STYLE = """QMainWindow, QDialog, QWidget#appRoot, QWidget#tabPage, QScrollArea {background:#f4f6f9;}
QWidget {color:#344054; font-family:'Microsoft YaHei UI'; font-size:10.5pt;}
QFrame#card {background:#fff; border:1px solid #dfe5ed; border-radius:7px;}
QWidget#sharedStatus {background:#fff; border-bottom:1px solid #e3e8ef;}
QFrame#footerBar {background:#fff; border-top:1px solid #dfe5ed;}
QLabel#sectionTitle {font-size:12pt; font-weight:600; color:#243b53; border:0;}
QLabel#pageTitle {font-size:14pt; font-weight:600; color:#243b53;}
QLabel#metaText, QLabel#secondaryText, QLabel#disabledValue {color:#596b80; font-size:9.5pt; border:0;}
QLabel#footerText {color:#596b80; font-size:9pt; border:0;}
QLabel#nextAction {color:#41566e; font-size:10pt; padding:0; background:transparent;}
QLabel#modeHint {color:#596b80; font-size:9.5pt; padding:0; background:transparent; border:0;}
QLabel#statusMessage {color:#41566e; font-size:10pt; border:0;}
QTabBar::tab {background:transparent; color:#596b80; padding:12px 17px; border-bottom:2px solid transparent;}
QTabBar::tab:selected {color:#285a95; border-bottom:2px solid #376da5; font-weight:600; background:#edf2f8;}
QTabBar::tab:hover {background:#eaf0f7;}
QTabBar::tab:focus {outline:1px solid #376da5;}
QScrollArea {border:0;}
QLineEdit, QComboBox, QTimeEdit {min-height:32px; border:1px solid #8798ab; border-radius:5px; background:#fff; padding:0 8px; selection-background-color:#376da5;}
QLineEdit:focus, QComboBox:focus, QTimeEdit:focus {border:2px solid #376da5; padding:0 7px;}
QLineEdit:disabled, QTimeEdit:disabled {background:#f1f3f6; color:#6b7b8f; border-color:#bec9d5;}
QPushButton {min-height:32px; padding:0 12px; color:#344d67; border:1px solid #9cacc0; border-radius:5px; background:#fff;}
QPushButton:hover {background:#edf2f8; border-color:#6e88a7;}
QPushButton:pressed {background:#dfe8f3;}
QPushButton:focus {border:2px solid #376da5;}
QPushButton:disabled {background:#edf0f4; color:#68798c; border-color:#c5cfdc;}
QPushButton#primaryButton {background:#376da5; color:#fff; border-color:#376da5;}
QPushButton#primaryButton:hover {background:#2b5989;}
QPushButton#primaryButton:disabled {background:#e0e7ef; color:#65788e; border-color:#c5cfdc;}
QPushButton#warningButton {color:#92502e; background:#fffaf5; border-color:#c7ab96;}
QPushButton#linkButton {color:#2e659e; border:0; background:transparent; padding:0 4px;}
QPushButton#linkButton:hover {background:#edf2f8;}
QCheckBox {spacing:8px; min-height:29px;}
QToolButton {min-height:17px; border:1px solid #9cacc0; border-radius:3px; background:#fff;}
QToolButton:hover {background:#eaf0f7;}
QTextEdit {border:1px solid #8798ab; background:#fff; border-radius:5px; padding:6px;}
QFrame[divider='true'] {background:#dfe5ed; min-height:1px; max-height:1px; border:0;}
"""


class TaskTabs(QWidget):
    """Native tab bar and stack with one persistent status strip between them."""
    currentChanged = Signal(int)

    def __init__(self):
        super().__init__()
        self.box = QVBoxLayout(self)
        self.box.setContentsMargins(0, 0, 0, 0)
        self.box.setSpacing(0)
        self.navigation = QHBoxLayout()
        self.navigation.setContentsMargins(4, 0, 18, 0)
        self.bar = QTabBar()
        self.bar.setExpanding(False)
        self.bar.setIconSize(QSize(16, 16))
        self.navigation.addWidget(self.bar)
        self.navigation.addStretch(1)
        self.box.addLayout(self.navigation)
        self.stack = QStackedWidget()
        self.box.addWidget(self.stack, 1)
        self.bar.currentChanged.connect(self.stack.setCurrentIndex)
        self.bar.currentChanged.connect(self.currentChanged)

    def setDocumentMode(self, value):
        self.bar.setDocumentMode(value)

    def setCornerWidget(self, widget):
        self.navigation.addWidget(widget)

    def addTab(self, widget, title):
        index = self.stack.addWidget(widget)
        self.bar.addTab(icon(("network", "clock", "settings")[index]), title)
        return index

    def currentIndex(self):
        return self.bar.currentIndex()

    def setCurrentIndex(self, index):
        self.bar.setCurrentIndex(index)

    def count(self):
        return self.bar.count()

    def tabText(self, index):
        return self.bar.tabText(index)

    def setTabText(self, index, text):
        self.bar.setTabText(index, text)

    def widget(self, index):
        return self.stack.widget(index)


def note(text):
    label = QLabel(text)
    label.setObjectName("secondaryText")
    label.setWordWrap(True)
    return label


def line(layout):
    frame = QFrame()
    frame.setProperty("divider", True)
    layout.addWidget(frame)


def row(*widgets, stretch=False):
    box = QWidget()
    layout = QHBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(12)
    for widget in widgets:
        layout.addWidget(widget, 1 if stretch and isinstance(widget, QLabel) else 0)
    if stretch and not any(isinstance(widget, QLabel) for widget in widgets):
        layout.addStretch(1)
    return box


def title_widget(text, kind, *, large=False):
    widget = QWidget()
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    glyph = QLabel()
    glyph.setPixmap(icon(kind).pixmap(QSize(18, 18)))
    glyph.setFixedSize(20, 20)
    layout.addWidget(glyph)
    label = QLabel(text)
    label.setObjectName("pageTitle" if large else "sectionTitle")
    layout.addWidget(label)
    layout.addStretch(1)
    return widget


def schedule_row(checkbox, control, disabled):
    box = QWidget()
    layout = QHBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)
    control.setFixedWidth(114)
    layout.addWidget(checkbox)
    layout.addStretch(1)
    layout.addWidget(disabled)
    layout.addWidget(control)
    return box


def section(title):
    box = QFrame()
    box.setObjectName("card")
    box.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
    layout = QVBoxLayout(box)
    layout.setContentsMargins(14, 12, 14, 14)
    layout.setSpacing(10)
    layout.setAlignment(Qt.AlignTop)
    names = {"网络连接":"network", "连接配置":"settings", "自动连接":"power", "时间安排":"clock", "联网后操作":"link", "运行状态":"network", "日志与版本":"document", "停用与维护":"shield"}
    heading = title_widget(title, names.get(title,"settings"))
    layout.addWidget(heading)
    return box, layout


def rebuild(window):
    """Move existing inputs to tabs; their signals and original handlers survive."""
    w = window
    old_root = w.centralWidget()
    root = QWidget()
    root.setObjectName("appRoot")
    layout = QVBoxLayout(root)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    # Keep legacy internal widgets alive, but never surface the post-1.4.3 survey.
    for widget in (w.dorm_protocol_observer_enabled, w.dorm_script_survey_button,
                   w.wireless_http_experimental):
        widget.setParent(root)
        widget.hide()
    w.dorm_protocol_observer_enabled.setChecked(False)
    w.wireless_http_experimental.setChecked(True)

    w.tabs = TaskTabs()
    w.tabs.setAccessibleName("功能标签页")
    w.tabs.setDocumentMode(True)
    w.help_button = QPushButton("帮助")
    w.help_button.setObjectName("linkButton")
    w.help_button.clicked.connect(w.show_usage)
    w.tabs.setCornerWidget(w.help_button)
    pages = []
    for title in ("连接", "自动化", "维护"):
        page = QWidget()
        page.setObjectName("tabPage")
        body = QVBoxLayout(page)
        body.setContentsMargins(16, 14, 16, 16)
        body.setSpacing(12)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(page)
        w.tabs.addTab(scroll, title)
        pages.append((page, body))
    w.connection_page, connection = pages[0]
    w.automation_page, automation = pages[1]
    w.maintenance_page, maintenance = pages[2]

    header = QWidget()
    header.setObjectName("sharedStatus")
    head = QVBoxLayout(header)
    head.setContentsMargins(20, 9, 20, 9)
    head.setSpacing(8)
    status_row = QHBoxLayout()
    status_row.setSpacing(8)
    for widget in (w.status_badge, w.status_title, w.monitor_label):
        status_row.addWidget(widget)
    status_row.addStretch(1)
    head.addLayout(status_row)
    w.next_action_label.setWordWrap(True)
    clock_mark = QLabel()
    clock_mark.setPixmap(icon("clock").pixmap(QSize(16, 16)))
    clock_mark.setFixedSize(18, 18)
    head.addWidget(row(clock_mark, w.next_action_label, stretch=True))
    w.status_card = header
    # Header is outside scrolling pages, below the tab strip via shared top layout.
    w.tabs.box.insertWidget(1, header)
    layout.addWidget(w.tabs, 1)

    w.manual_card, actions = section("网络连接")
    w.status_label.setParent(root)
    w.status_label.hide()
    actions.addWidget(row(w.native_verify_button, w.login_validate_button,
                          w.reauthenticate_button, stretch=True))
    actions.addWidget(w.native_verify_hint)
    connection.addWidget(w.manual_card)
    w.account_card, details = section("连接配置")
    w.details_container = QWidget()
    form = QFormLayout(w.details_container)
    w.connection_form = form
    form.setContentsMargins(0, 0, 0, 0)
    form.setHorizontalSpacing(18)
    form.setVerticalSpacing(9)
    form.setFormAlignment(Qt.AlignTop)
    form.setRowWrapPolicy(QFormLayout.WrapLongRows)
    form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
    mode_label = QLabel("连接方式")
    mode_label.setBuddy(w.connection_mode)
    form.addRow(mode_label, w.connection_mode)
    form.addRow("", w.connection_mode_hint)
    form.addRow("校园网账号", row(w.credentials_hint, w.edit_credentials_button, stretch=True))
    form.addRow("", w.credentials_editor)
    w.credentials_note = note("账号和密码留空可保留原凭据；更换时请同时填写。")
    form.addRow("", w.credentials_note)
    w.operator_label.setText("运营商")
    w.operator_label.setBuddy(w.operator)
    form.addRow(w.operator_label, w.operator)
    # 锐捷客户端路径改在“检查锐捷认证”弹窗内选择，主界面不再展示
    w.ruijie_path_label.setText("锐捷客户端")
    w.ruijie_path_label.setBuddy(w.ruijie_path)
    w.ruijie_path_label.setParent(w.details_container)
    w.ruijie_path_row.setParent(w.details_container)
    w.ruijie_path_label.hide()
    w.ruijie_path_row.hide()
    w.native_fallback_row.setParent(w.details_container)
    form.addRow("", w.native_fallback_row)
    w.wireless_strategy = note("认证方式：优先无浏览器认证，失败后安全回退至 Chrome / Edge。")
    form.addRow("", w.wireless_strategy)
    details.addWidget(w.details_container)
    connection.addWidget(w.account_card)
    connection.addWidget(note("修改配置后，请点击“保存并应用”；切换标签页不会丢失修改。"))
    connection.addStretch(1)

    w.automation_card, auto = section("自动连接")
    auto.addWidget(w.auto_connect_on_startup)
    automation.addWidget(w.automation_card)
    schedule, times = section("时间安排")
    w.wake_enabled.setText("每天定时唤醒")
    w.wake_enabled.setToolTip("按设定时间唤醒电脑；沿用原版唤醒后的联网检查与恢复流程，与开机后自动联网开关独立。")
    times.addWidget(schedule_row(w.wake_enabled, w.wake_time_control, w.wake_disabled_label))
    times.addWidget(schedule_row(w.hibernate_enabled, w.sleep_time_control, w.sleep_disabled_label))
    automation.addWidget(schedule)
    after, after_layout = section("联网后操作")
    after_layout.addWidget(w.start_uu)
    w.uu_path_label.setText("UU 程序位置")
    w.uu_path_label.setBuddy(w.uu_path)
    after_layout.addWidget(w.uu_path_label)
    after_layout.addWidget(w.uu_path_row)
    after_layout.addWidget(w.keep_login_page_open)
    automation.addWidget(after)
    automation.addWidget(w._section_title("设置预览"))
    automation.addWidget(w.schedule_hint)
    automation.addStretch(1)

    running, running_layout = section("运行状态")
    w.maintenance_status = note("尚未读取运行状态")
    running_layout.addWidget(w.maintenance_status)
    running_layout.addWidget(w.task_label)
    maintenance.addWidget(running)
    logs, logs_layout = section("日志与版本")
    w.log_button.setText("打开日志")
    w.log_button.setObjectName("compactButton")
    w.log_button.setIcon(icon("folder"))
    logs_layout.addWidget(row(note("运行日志已过滤敏感信息。"), w.log_button, stretch=True))
    logs_layout.addWidget(note(f"程序版本：{w.product_version}"))
    maintenance.addWidget(logs)
    w.management_card.setParent(w.maintenance_page)
    w.management_card.layout().setContentsMargins(14, 12, 14, 14)
    old_heading = w.management_card.layout().takeAt(0)
    if old_heading and old_heading.widget():
        old_heading.widget().deleteLater()
    w.management_card.layout().insertWidget(0, title_widget("停用与维护", "shield"))
    maintenance.addWidget(w.management_card)
    maintenance.addStretch(1)

    w.footer_bar.setParent(root)
    for label in w.footer_bar.findChildren(QLabel):
        if label.objectName() == "footerText":
            if label.text().startswith("凭据"):
                label.setToolTip(label.text())
                label.setText("凭据安全保存 · 日志已脱敏")
                label.setMinimumWidth(220)
            label.setWordWrap(False)
    w.configure_button.setText("保存并应用")
    w.configure_button.setMinimumWidth(132)
    layout.addWidget(w.footer_bar)
    for widget, name in ((w.username, "校园网账号"), (w.password, "校园网密码"),
                         (w.ruijie_path, "锐捷客户端位置"), (w.uu_path, "UU 程序位置")):
        widget.setAccessibleName(name)
    w.status_title.setObjectName("metaText")
    w.setMinimumSize(480, 640)
    w.resize(560, 780)
    w.setCentralWidget(root)
    w.root_layout = layout
    w._apply_styles()
    w.update_connection_mode_hint()
    w.update_uu_controls()
    w.update_schedule_controls()
    sync_rows(w)
    # Former containers are intentionally not used by the new layout.
    old_root.deleteLater()


def sync_rows(w):
    """Hide complete form rows, including their empty labels, to avoid phantom gaps."""
    if not hasattr(w, "connection_form"):
        return
    workstation = w.connection_mode.currentData() == "workstation_ruijie"
    wireless = w.connection_mode.currentData() == "wireless"
    form = w.connection_form
    form.setRowVisible(w.credentials_editor, not w.credentials_editor.isHidden())
    form.setRowVisible(w.credentials_note, not w.credentials_editor.isHidden())
    show_ruijie_controls = workstation
    form.setRowVisible(w.native_fallback_row, workstation)
    w.rawether_check_button.setVisible(
        show_ruijie_controls and w.ruijie_background_client_fallback.isChecked())
    w.rawether_check_status.setVisible(
        show_ruijie_controls and w.ruijie_background_client_fallback.isChecked())
    w.ruijie_path_row.hide()
    w.ruijie_path_label.hide()
    form.setRowVisible(w.operator, not workstation)
    form.setRowVisible(w.wireless_strategy, wireless)
