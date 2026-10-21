"""One-time scoped source migration; run only in the isolated 1.5 directory."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
assert ROOT.name == 'njmu-campus-net-assistant-1.5'
base = ROOT / 'src/campus_net_assistant'
p = base / 'gui.py'
s = p.read_text(encoding='utf8')
s = s.replace('        self.setWindowTitle(PRODUCT_NAME)\n', '        self.setWindowTitle(PRODUCT_NAME)\n        self.product_version = PRODUCT_VERSION\n        self._settings_dirty = False\n', 1)
s = s.replace('        self.tray = QSystemTrayIcon(self)', '        from .ui_layout import rebuild\n        rebuild(self)\n\n        self.tray = QSystemTrayIcon(self)', 1)
start = s.index('    def _apply_styles(self)')
end = s.index('    def _mark_settings_dirty', start)
s = s[:start] + '''    def _apply_styles(self) -> None:
        from .ui_layout import STYLE
        self.setStyleSheet(STYLE)

''' + s[end:]
s = s.replace('        self.settings_status_label.setText("有未保存的修改")', '        self._settings_dirty = True\n        self.settings_status_label.setText("有未应用的修改（所有标签页）")')
s = s.replace('        self.settings_status_label.setText("设置已保存")', '        self._settings_dirty = False\n        self.settings_status_label.setText("设置已保存")')
# The selected form mode is a draft, not current connection evidence.
a = s.index('        self.status_title.setText(', s.index('    def update_connection_mode_hint'))
b = s.index('        if selected_mode == CONNECTION_MODE_DORM_ETHERNET:', a)
s = s[:a] + s[b:]
a = s.index('        self.wireless_http_experimental.setVisible(', s.index('    def update_connection_mode_hint'))
b = s.index('        if not self._manual_action_is_running():', a)
s = s[:a] + '''        self.wireless_http_experimental.hide()
        self.dorm_protocol_observer_enabled.hide()
        self.dorm_script_survey_button.hide()
        if hasattr(self, "wireless_strategy"):
            self.wireless_strategy.setVisible(selected_mode == CONNECTION_MODE_WIRELESS)
''' + s[b:]
s = s.replace('        self.config = load_config()\n\n    @Slot()\n    def select_ruijie_path', '        # The dialog owns only its path field; preserve unsaved values in other tabs.\n\n    @Slot()\n    def select_ruijie_path', 1)
s = s.replace('"收起账号输入" if visible else "重新输入"', '"收起账号输入" if visible else "更换账号或密码"')
s = s.replace('保存设置并更新自动化', '保存并应用')
s = s.replace('self.config.wireless_http_experimental = self.wireless_http_experimental.isChecked()', 'self.config.wireless_http_experimental = True')
s = s.replace('self.config.dorm_protocol_observer_enabled = (\n                self.dorm_protocol_observer_enabled.isChecked()\n            )', 'self.config.dorm_protocol_observer_enabled = False')
s = s.replace('self.config.dorm_protocol_observer_enabled = (\n            self.dorm_protocol_observer_enabled.isChecked()\n        )', 'self.config.dorm_protocol_observer_enabled = False')
# Use applied schedule for persistent next-task status; the editable preview stays local.
s = s.replace('if self.wake_enabled.isChecked():\n            candidates.append((self._next_occurrence(now, self.wake_time.time())', 'if self.config.wake_enabled:\n            candidates.append((self._next_occurrence(now, QTime.fromString(self.config.wake_time, "HH:mm"))')
s = s.replace('if self.hibernate_enabled.isChecked():\n            candidates.append((self._next_occurrence(now, self.sleep_time.time())', 'if self.config.hibernate_enabled:\n            candidates.append((self._next_occurrence(now, QTime.fromString(self.config.sleep_time, "HH:mm"))')
s = s.replace('        self._update_network_actions(status)\n', '''        self._update_network_actions(status)
        applied_mode = status.get("connection_mode") or self.config.connection_mode
        self.status_title.setText({
            CONNECTION_MODE_WIRELESS: "全校无线网",
            CONNECTION_MODE_DORM_ETHERNET: "宿舍有线网",
            CONNECTION_MODE_WORKSTATION_RUIJIE: "工位有线网",
        }.get(applied_mode, "校园网连接"))
        if hasattr(self, "maintenance_status"):
            timestamp = str(status.get("time") or "尚无时间记录")
            self.maintenance_status.setText(
                f"{self.status_badge.text()} · {self.status_label.text()}\\n最近状态时间：{timestamp}"
            )
''', 1)
# Navigating to credentials on errors must reveal the relevant tab.
s = s.replace('        self.credentials_editor.setVisible(visible)', '        if visible and hasattr(self, "tabs"):\n            self.tabs.setCurrentIndex(0)\n        self.credentials_editor.setVisible(visible)')
pos=s.index('    def open_logs(self)')
s=s[:pos]+'''    def show_usage(self) -> None:
        import os
        target = Path(sys.executable).parent / "使用说明.txt" if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2] / "使用说明.txt"
        try:
            os.startfile(str(target))
        except OSError:
            QMessageBox.information(self, "使用说明", f"说明文件：{target}")

'''+s[pos:]
p.write_text(s,encoding='utf8')
p=base/'version.py';p.write_text('"""Single authoritative product version."""\n\nVERSION = "1.5"\n',encoding='utf8')
p=base/'config.py';s=p.read_text(encoding='utf8').replace('wireless_http_experimental: bool = False','wireless_http_experimental: bool = True')
# Migrate existing configs including an explicit old experimental false value.
s=s.replace('    config.monitor_interval_seconds = NORMAL_MONITOR_INTERVAL_SECONDS', '    config.wireless_http_experimental = True\n    config.dorm_protocol_observer_enabled = False\n    config.monitor_interval_seconds = NORMAL_MONITOR_INTERVAL_SECONDS')
p.write_text(s,encoding='utf8')
p=base/'controller.py';s=p.read_text(encoding='utf8')
s=s.replace('if config.wireless_http_experimental and not dorm_ethernet:', 'if not dorm_ethernet:')
s=s.replace('开始实验性无浏览器无线网认证预检','开始无浏览器优先无线网认证预检')
s=s.replace('                dorm_protocol_observer_enabled=config.dorm_protocol_observer_enabled,\n','')
p.write_text(s,encoding='utf8')
print('Migrated GUI presentation, explicit wireless priority and version only.')
