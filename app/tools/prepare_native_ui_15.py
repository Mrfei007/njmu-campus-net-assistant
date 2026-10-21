"""Scoped native dialog presentation migration; keeps authentication worker logic."""
import ast
from pathlib import Path

p=Path(__file__).resolve().parents[1]/'src/campus_net_assistant/native_wired_gui.py'
s=p.read_text(encoding='utf8')
s=s.replace('QDialog, QLabel, QMessageBox, QPushButton, QTextEdit, QVBoxLayout,','QDialog, QLabel, QMessageBox, QPushButton, QTextEdit, QVBoxLayout,\n    QLineEdit, QHBoxLayout, QFileDialog, QFormLayout, QWidget,')
s=s.replace('def __init__(self, action: str, paths: list[str] | None = None)', 'def __init__(self, action: str, paths: list[str] | None = None, *, client_path: str | None = None)')
s=s.replace('        self.paths = paths or []','        self.paths = paths or []\n        self.client_path = client_path')
s=s.replace('            config = load_config()','''            config = load_config()
            if self.client_path is not None:
                if config.ruijie_path.casefold() != self.client_path.casefold():
                    config.ruijie_auto_enabled = False
                    config.ruijie_native_auto_enabled = False
                    config.ruijie_confirmed_worker_sha256 = ""
                config.ruijie_path = self.client_path
''',1)
a=s.index('    def __init__(self, parent=None)',s.index('class NativeWiredDialog'))
b=s.index('    @Slot()\n    def confirm_md5_probe',a)
s=s[:a]+'''    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        from .ui_layout import STYLE, line, note
        self.setStyleSheet(STYLE)
        self.setWindowTitle("工位有线网 · 锐捷认证")
        self.resize(760, 620)
        self.setMinimumSize(620, 540)
        self.thread = self.worker = None
        self._check_passed = False
        self._checked_path = ""
        self._last_action = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 18)
        layout.setSpacing(12)
        title = QLabel("锐捷认证设置")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addWidget(note("选择学校客户端，检查接入条件后启用。"))
        layout.addWidget(QLabel("客户端位置"))
        parent_path = getattr(parent, "ruijie_path", None)
        self.client_path = QLineEdit(parent_path.text() if parent_path is not None else load_config(read_only=True).ruijie_path)
        self.client_path.setAccessibleName("锐捷客户端位置")
        self.client_path.setPlaceholderText("选择 RuijieSupplicant.exe")
        self.browse_button = QPushButton("浏览…")
        self.browse_button.setAccessibleName("选择锐捷客户端")
        path_row = QHBoxLayout()
        path_row.addWidget(self.client_path, 1)
        path_row.addWidget(self.browse_button)
        layout.addLayout(path_row)
        layout.addWidget(note("支持手动输入路径；修改后需重新检查。"))
        self.check_button = QPushButton("检查接入条件")
        check_row = QHBoxLayout()
        check_row.addStretch(1)
        check_row.addWidget(self.check_button)
        layout.addLayout(check_row)
        line(layout)
        title = QLabel("接入检查")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        result_form = QFormLayout()
        result_form.setHorizontalSpacing(32)
        result_form.setVerticalSpacing(10)
        self.check_values = {}
        for key, caption in (("client", "客户端"), ("link", "物理有线网卡"), ("profile", "兼容版本")):
            value = QLabel("待检查")
            value.setObjectName("secondaryText")
            self.check_values[key] = value
            result_form.addRow(caption, value)
        layout.addLayout(result_form)
        layout.addWidget(note("检查不发起认证，也不读取账号密码。"))
        line(layout)
        title = QLabel("认证与保活")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        layout.addWidget(note("启用前，请先在官方客户端注销，并保持网线连接。"))
        layout.addWidget(note("启用将发起实际认证，成功后验证联网并启动后台保活。"))
        self.summary = note("尚未检查接入条件。")
        layout.addWidget(self.summary)
        self.details_button = QPushButton("查看检查详情")
        self.details_button.setObjectName("linkButton")
        layout.addWidget(self.details_button)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setAccessibleName("检查和认证详情")
        self.result_text.setMinimumHeight(100)
        self.result_text.setVisible(False)
        layout.addWidget(self.result_text, 1)
        self.details_button.clicked.connect(lambda: self.result_text.setVisible(self.result_text.isHidden()))
        self.restore_button = QPushButton("恢复原有有线设置")
        self.restore_button.setObjectName("warningButton")
        self.restore_button.setVisible(False)
        layout.addWidget(self.restore_button)
        layout.addStretch(1)
        line(layout)
        footer = QHBoxLayout()
        footer.addStretch(1)
        self.cancel_button = QPushButton("关闭")
        footer.addWidget(self.cancel_button)
        self.md5_button = QPushButton("验证并启用")
        self.md5_button.setObjectName("primaryButton")
        self.md5_button.setEnabled(False)
        footer.addWidget(self.md5_button)
        layout.addLayout(footer)
        self.cancel_button.clicked.connect(self.reject)
        self.client_path.textChanged.connect(self.path_changed)
        self.browse_button.clicked.connect(self.select_client)
        self.check_button.clicked.connect(lambda: self.start("check"))
        self.md5_button.clicked.connect(self.confirm_md5_probe)
        self.restore_button.clicked.connect(lambda: self.start("restore"))

    def path_changed(self) -> None:
        self._check_passed = False
        self._checked_path = ""
        self.md5_button.setEnabled(False)
        self.summary.setText("客户端位置已修改，请重新检查。")
        for value in self.check_values.values():
            value.setText("待检查")
        parent_path = getattr(self.parent(), "ruijie_path", None)
        if parent_path is not None:
            parent_path.setText(self.client_path.text())

    def select_client(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(self, "选择学校锐捷客户端", self.client_path.text(), "锐捷客户端 (RuijieSupplicant.exe 8021x.exe);;可执行程序 (*.exe)")
        if selected:
            self.client_path.setText(selected)

''' + s[b:]
s=s.replace('    def confirm_md5_probe(self) -> None:\n', '''    def confirm_md5_probe(self) -> None:
        if not self._check_passed or self._checked_path != self.client_path.text().strip():
            QMessageBox.information(self, "需要检查", "请先检查当前客户端位置与接入条件。")
            return
''')
s=s.replace('        for button in (self.check_button, self.md5_button, self.restore_button):\n            button.setEnabled(False)', '''        self._last_action = action
        self.client_path.setEnabled(False)
        self.browse_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        for button in (self.check_button, self.md5_button, self.restore_button):
            button.setEnabled(False)''')
s=s.replace('        self.worker = NativeWorker(action, paths)', '        self.worker = NativeWorker(action, paths, client_path=self.client_path.text().strip())')
s=s.replace('    def show_result(self, result: dict) -> None:\n', '''    def show_result(self, result: dict) -> None:
        if self._last_action == "check":
            raw = result.get("rawether", {})
            client_ready = bool(raw.get("reuse_candidate") and raw.get("bridge_ready"))
            link_ready = bool(result.get("link_ready"))
            profile_ready = bool(result.get("compatibility_profile_ready"))
            self.check_values["client"].setText("已核验" if client_ready else "未通过，请查看详情")
            self.check_values["link"].setText("已连接" if link_ready else "未就绪")
            self.check_values["profile"].setText("已匹配" if profile_ready else "未匹配")
            self._check_passed = client_ready and link_ready and profile_ready and not result.get("restore_pending")
            self._checked_path = self.client_path.text().strip() if self._check_passed else ""
            self.summary.setText("检查通过。请在官方客户端注销后验证启用。" if self._check_passed else "接入条件未通过，请查看详情后重新检查。")
        else:
            self.summary.setText(str(result.get("message") or ("操作完成" if result.get("success") else "操作未完成，请查看详情")))
''')
s=s.replace('        for button in (self.check_button, self.md5_button, self.restore_button):\n            button.setEnabled(True)', '''        for widget in (self.check_button, self.restore_button, self.client_path, self.browse_button, self.cancel_button):
            widget.setEnabled(True)
        self.md5_button.setEnabled(self._check_passed and self._checked_path == self.client_path.text().strip())''')
p.write_text(s,encoding='utf8')
print('Native dialog migrated; worker authentication actions retained.')
