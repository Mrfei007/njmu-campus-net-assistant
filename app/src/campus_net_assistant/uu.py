from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def ensure_running(path: Path) -> tuple[bool, str]:
    if os.name != "nt":
        return False, "UU 远程控制仅支持 Windows"
    try:
        process = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", "Get-Process -Name GameViewer -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Id"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
        if process.stdout.strip():
            return True, "GameViewer.exe 已在运行"
        if not path.exists():
            return False, "未找到 UU 远程控制程序"
        subprocess.Popen([str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)
        deadline = time.time() + 25
        while time.time() < deadline:
            time.sleep(2)
            check = subprocess.run(
                ["tasklist.exe", "/FI", "IMAGENAME eq GameViewer.exe", "/NH"],
                capture_output=True,
                text=True,
                encoding="mbcs",
                errors="replace",
                timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            if "GameViewer.exe" in check.stdout:
                return True, "GameViewer.exe 已启动"
        return False, "UU 远程控制程序未在 25 秒内启动"
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"UU 状态检查失败：{type(error).__name__}"
