from __future__ import annotations

import json
from datetime import datetime

from .config import APP_DIR


STATUS_PATH = APP_DIR / "status.json"


def write(stage: str, success: bool | None, message: str, **fields: object) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "stage": stage,
        "success": success,
        "message": message,
        **fields,
    }
    STATUS_PATH.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def read() -> dict:
    try:
        return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"stage": "not-started", "success": None, "message": "尚未运行"}
