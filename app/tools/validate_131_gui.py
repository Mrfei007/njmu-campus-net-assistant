"""离屏渲染当前版本主界面，不创建任务，也不发起真实认证。"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "output" / "ui-131-validation"
RUNTIME_DIR = OUTPUT_DIR / "gui-runtime"
OUTPUT_PATH = OUTPUT_DIR / "main-window-131.png"

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["LOCALAPPDATA"] = str(RUNTIME_DIR)
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent / "campus-net-assistant" / "vendor"))

from PySide6.QtGui import QFont, QFontDatabase  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from campus_net_assistant.config import (  # noqa: E402
    AppConfig,
    CONNECTION_MODE_WORKSTATION_RUIJIE,
)
from campus_net_assistant.gui import MainWindow  # noqa: E402


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    font_id = QFontDatabase.addApplicationFont(r"C:\Windows\Fonts\msyh.ttc")
    families = QFontDatabase.applicationFontFamilies(font_id)
    app.setFont(QFont(families[0] if families else "Microsoft YaHei UI", 10))
    config = AppConfig(
        connection_mode=CONNECTION_MODE_WORKSTATION_RUIJIE,
        auto_connect_on_startup=True,
        wake_enabled=True,
        wake_time="08:55",
        start_uu=True,
        uu_path=r"D:\UU远程\GameViewer\GameViewer.exe",
        hibernate_enabled=False,
        ruijie_path=r"C:\Program Files\Ruijie Supplicant\RuijieSupplicant.exe",
    )
    status = {
        "stage": "online",
        "success": True,
        "current_online": True,
        "message": "工位有线已连接；当前联网探测成功；后台保活正常",
        "monitor_policy": "active",
    }
    with (
        patch("campus_net_assistant.gui.load_config", return_value=config),
        patch(
            "campus_net_assistant.gui.installed_task_names",
            return_value=["NJMUCampusNetAssistant-Monitor", "NJMUCampusNetAssistant-Wake"],
        ),
        patch("campus_net_assistant.gui.is_admin", return_value=False),
        patch("campus_net_assistant.gui.read_status", return_value=status),
        patch("campus_net_assistant.gui.load_credentials", return_value=("demo", "secret")),
    ):
        window = MainWindow()
        window.resize(1100, 760)
        window.show()
        app.processEvents()
        assert window.windowTitle() == "NJMU校园网自动化连接程序"
        assert window.status_badge.text() == "已联网"
        assert window.status_title.text() == "工位有线网"
        assert window.login_button.isVisible()
        assert not window.login_validate_button.isVisible()
        assert window.footer_bar.isVisible()
        if not window.grab().save(str(OUTPUT_PATH), "PNG"):
            raise RuntimeError(f"无法保存界面截图：{OUTPUT_PATH}")
        window.timer.stop()
        window.tray.hide()
        window._allow_close = True
        window.close()
        app.processEvents()
    print(OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
