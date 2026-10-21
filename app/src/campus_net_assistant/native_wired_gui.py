"""Read-only check dialog for the optional Rawether driver fallback."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, QObject, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from .logging_redacted import event
from .native_backend_check import rawether_environment
from .native_backend_state import fallback_status, mark_fallback_checked


class RawetherCheckWorker(QObject):
    finished = Signal(dict)

    def __init__(self, configured_path: str) -> None:
        super().__init__()
        self.configured_path = configured_path

    @Slot()
    def run(self) -> None:
        try:
            result = rawether_environment(self.configured_path)
        except Exception as error:
            result = {
                "success": False,
                "message": f"检查未完成（{type(error).__name__}）",
                "rows": [],
            }
        self.finished.emit(result)


class RawetherFallbackDialog(QDialog):
    """Only checks official Ruijie components; never authenticates."""

    def __init__(self, parent=None, configured_path: str = "") -> None:
        super().__init__(parent)
        from .ui_layout import STYLE, note, title_widget

        self.setStyleSheet(STYLE)
        self.setWindowTitle("锐捷驱动检查")
        self.resize(560, 460)
        self.setMinimumSize(460, 380)
        self.thread: QThread | None = None
        self.worker: RawetherCheckWorker | None = None
        self.result: dict = {}
        self.checked_client_path = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 14)
        layout.setSpacing(10)
        layout.addWidget(title_widget("锐捷驱动检查", "network", large=True))
        layout.addWidget(note(
            "只读检查官方锐捷客户端的驱动组件，用于本程序的原生 Rawether 后备连接；"
            "不会启动锐捷客户端、不会发起认证、不会读取账号密码。"
        ))
        layout.addWidget(QLabel("客户端位置"))
        self.client_path = QLineEdit(configured_path)
        self.client_path.setPlaceholderText("选择 RuijieSupplicant.exe")
        self.client_path.setAccessibleName("锐捷客户端位置")
        browse = QPushButton("浏览…")
        browse.clicked.connect(self._browse)
        path_row = QHBoxLayout()
        path_row.addWidget(self.client_path, 1)
        path_row.addWidget(browse)
        layout.addLayout(path_row)
        layout.addWidget(note("修改客户端路径后需要重新检查。"))
        self.check_button = QPushButton("检查兜底可用性")
        self.check_button.clicked.connect(self._start_check)
        layout.addWidget(self.check_button)
        self.result_label = QLabel("尚未检查")
        self.result_label.setWordWrap(True)
        layout.addWidget(self.result_label)
        self.details_label = QLabel("")
        self.details_label.setWordWrap(True)
        self.details_label.setTextInteractionFlags(self.details_label.textInteractionFlags())
        layout.addWidget(self.details_label, 1)
        footer = QHBoxLayout()
        footer.addStretch(1)
        close_button = QPushButton("关闭")
        close_button.clicked.connect(self.accept)
        footer.addWidget(close_button)
        layout.addLayout(footer)
        self._refresh_status()

    def _refresh_status(self) -> None:
        path = self.client_path.text().strip()
        status = fallback_status(path)
        self.result_label.setText(
            "检查通过：可作为原生认证失败后的后备连接"
            if (path and status["valid"]) else "尚未通过检查"
        )

    @Slot()
    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择锐捷客户端", self.client_path.text(), "可执行文件 (*.exe)")
        if path:
            self.client_path.setText(path)
            self._refresh_status()

    @Slot()
    def _start_check(self) -> None:
        if self.thread is not None:
            return
        path = self.client_path.text().strip()
        if not path:
            QMessageBox.warning(self, "缺少客户端路径", "请先选择锐捷客户端主程序。")
            return
        self.check_button.setEnabled(False)
        self.result_label.setText("正在只读检查驱动组件…")
        self.details_label.setText("")
        self.thread = QThread(self)
        self.worker = RawetherCheckWorker(path)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._show_result)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    @Slot(dict)
    def _show_result(self, result: dict) -> None:
        self.result = result
        success = bool(result.get("success"))
        rows = result.get("rows") or []
        lines = []
        for row in rows:
            label = str(row.get("label", ""))
            value = str(row.get("value", ""))
            mark = ""
            ok = row.get("ok")
            if ok is True:
                mark = "✓ "
            elif ok is False:
                mark = "✗ "
            lines.append(f"{mark}{label}：{value}")
        self.details_label.setText("\n".join(lines))
        if success:
            self.checked_client_path = str(result.get("client_path") or self.client_path.text())
            mark_fallback_checked(result.get("record") or {})
            self.result_label.setText("检查通过：可作为原生认证失败后的后备连接")
            event("rawether-fallback-check", True, "锐捷驱动后备连接检查通过",
                  client_path=Path(self.checked_client_path).name)
        else:
            message = str(result.get("message") or "检查未通过")
            self.result_label.setText("检查未通过：" + message)
            event("rawether-fallback-check", False, "锐捷驱动后备连接检查未通过",
                  reason=message)
        self._refresh_status()

    @Slot()
    def _thread_finished(self) -> None:
        self.thread = None
        self.worker = None
        self.check_button.setEnabled(True)
