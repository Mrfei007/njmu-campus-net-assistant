"""Locate the official Ruijie client files used as the Rawether component source.

The application no longer drives the official client UI.  Only installation
resolution and file hashes are kept so the optional Rawether fallback can be
checked in read-only fashion.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


RUIJIE_WORKER_NAME = "8021x.exe"
RUIJIE_LAUNCHER_NAME = "RuijieSupplicant.exe"


class RuijieSafetyError(RuntimeError):
    def __init__(self, reason: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.reason = reason
        self.details = details


@dataclass(frozen=True)
class RuijieInstallation:
    launcher: Path
    worker: Path
    worker_sha256: str


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_installation(configured_path: str | Path) -> RuijieInstallation:
    raw = str(configured_path).strip().strip('"')
    if not raw:
        raise RuijieSafetyError("client-path-missing", "尚未选择官方锐捷客户端")
    selected = Path(raw).expanduser()
    try:
        selected = selected.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuijieSafetyError("client-path-invalid", "所选锐捷客户端路径不存在") from error
    if not selected.is_file() or selected.suffix.casefold() != ".exe":
        raise RuijieSafetyError("client-path-invalid", "所选路径不是锐捷客户端可执行文件")
    if selected.name.casefold() not in {
        RUIJIE_LAUNCHER_NAME.casefold(),
        RUIJIE_WORKER_NAME.casefold(),
    }:
        raise RuijieSafetyError(
            "client-path-untrusted",
            f"只允许选择 {RUIJIE_LAUNCHER_NAME} 或 {RUIJIE_WORKER_NAME}",
        )
    folder = selected.parent
    worker = folder / RUIJIE_WORKER_NAME
    launcher = folder / RUIJIE_LAUNCHER_NAME
    if not worker.is_file():
        raise RuijieSafetyError("client-files-incomplete", "客户端目录缺少 8021x.exe")
    if not launcher.is_file():
        launcher = worker
    return RuijieInstallation(
        launcher=launcher.resolve(),
        worker=worker.resolve(),
        worker_sha256=_file_sha256(worker),
    )
