"""Privacy-bounded collection of official dorm-portal static JavaScript.

The collector never replays a login, sends credentials, follows redirects, or
copies portal HTML/API bodies.  It reads only script paths already present in a
completed metadata-only observer capture, then performs cookie-free GETs bound
to the selected dorm Ethernet IPv4 address.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from .config import APP_DIR
from .dorm_observer import CAPTURE_DIR, PORTAL_HOST, PORTAL_SCHEME


SURVEY_DIR = APP_DIR / "diagnostics" / "dorm-static-script-survey"
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_RECORDS = 5000
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_SCRIPT_BYTES = 16 * 1024 * 1024
MAX_SCRIPTS = 64
SCRIPT_MEDIA_TYPES = {
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
}
ANALYSIS_IDENTIFIERS = (
    "flowKey",
    "sessionId",
    "flowSessionId",
    "ttbYz9WP",
    "/cas-sso/login",
    "/eportal/network/serviceSelection",
    "/eportal/network/serviceLogin",
    "login-croypto",
)
SCRIPT_PATH_RE = re.compile(
    r"^/portal/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.js$"
)


class DormScriptSurveyError(RuntimeError):
    """The survey could not remain inside its verified read-only boundary."""


@dataclass(frozen=True)
class ScriptDownload:
    status: int
    content_type: str
    body: bytes


@dataclass(frozen=True)
class DormScriptSurveyResult:
    archive_path: Path
    output_dir: Path
    script_count: int
    total_bytes: int
    source_capture: str


def _validated_interface_ip(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError) as error:
        raise DormScriptSurveyError("宿舍有线接口 IPv4 地址无效") from error
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise DormScriptSurveyError("宿舍有线接口 IPv4 地址不可用于调查")
    return str(address)


def _validated_script_path(value: object) -> str | None:
    path = str(value or "")
    if not SCRIPT_PATH_RE.fullmatch(path):
        return None
    if any(segment in {".", ".."} for segment in path.split("/")):
        return None
    return path


def _capture_script_paths(path: Path) -> tuple[bool, list[str]]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CAPTURE_BYTES:
            return False, []
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False, []
    if len(lines) > MAX_CAPTURE_RECORDS:
        return False, []
    complete = False
    profile_ok = False
    paths: set[str] = set()
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False, []
        if not isinstance(record, dict):
            return False, []
        event_name = record.get("event")
        if event_name == "capture-started":
            profile_ok = (
                record.get("privacy_profile") in {"metadata-only-v1", "metadata-only-v2"}
                and record.get("portal_host") == PORTAL_HOST
            )
        elif event_name == "capture-stopped" and record.get("complete") is True:
            complete = True
        elif event_name == "response":
            target = record.get("target") if isinstance(record.get("target"), dict) else {}
            media_type = str(record.get("mime_type") or "").split(";", 1)[0].strip().lower()
            candidate = _validated_script_path(target.get("path"))
            if (
                record.get("status") == 200
                and media_type in SCRIPT_MEDIA_TYPES
                and target.get("scheme") == PORTAL_SCHEME
                and target.get("host") == PORTAL_HOST
                and candidate is not None
            ):
                paths.add(candidate)
    return bool(profile_ok and complete), sorted(paths)[:MAX_SCRIPTS]


def find_latest_complete_capture(capture_dir: Path = CAPTURE_DIR) -> tuple[Path, list[str]]:
    try:
        candidates = sorted(
            (item for item in capture_dir.glob("capture-*.jsonl") if item.is_file()),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
    except OSError as error:
        raise DormScriptSurveyError("无法读取宿舍门户观察记录目录") from error
    for candidate in candidates:
        complete, paths = _capture_script_paths(candidate)
        if complete and paths:
            return candidate, paths
    raise DormScriptSurveyError("没有找到包含官方静态脚本的完整宿舍门户观察记录")


def _fetch_script_http(path: str, interface_ip: str) -> ScriptDownload:
    candidate = _validated_script_path(path)
    if candidate is None:
        raise DormScriptSurveyError("静态脚本路径不在官方门户白名单内")
    interface_ip = _validated_interface_ip(interface_ip)
    connection = http.client.HTTPConnection(
        PORTAL_HOST,
        80,
        timeout=12,
        source_address=(interface_ip, 0),
    )
    try:
        connection.request(
            "GET",
            candidate,
            headers={
                "Accept": "application/javascript,text/javascript;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "User-Agent": "NJMUCampusNetAssistant-StaticScriptSurvey/1",
            },
        )
        response = connection.getresponse()
        content_type = str(response.getheader("Content-Type", ""))
        content_encoding = str(response.getheader("Content-Encoding", "")).strip().lower()
        content_length = str(response.getheader("Content-Length", "")).strip()
        if content_encoding not in {"", "identity"}:
            raise DormScriptSurveyError("官方静态脚本返回了不支持的压缩编码")
        if content_length.isdigit() and int(content_length) > MAX_SCRIPT_BYTES:
            raise DormScriptSurveyError("官方静态脚本超过单文件大小上限")
        body = response.read(MAX_SCRIPT_BYTES + 1)
        return ScriptDownload(int(response.status), content_type, body)
    except (OSError, http.client.HTTPException) as error:
        raise DormScriptSurveyError("读取官方门户静态脚本失败") from error
    finally:
        connection.close()


def _script_file_name(index: int, path: str, digest: str) -> str:
    basename = Path(path).name
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}\.js", basename):
        basename = f"script-{digest[:12]}.js"
    return f"{index:02d}-{basename}"


def _analysis_for_scripts(files: list[dict[str, object]], bodies: dict[str, bytes]) -> dict[str, object]:
    identifiers: dict[str, list[dict[str, object]]] = {
        identifier: [] for identifier in ANALYSIS_IDENTIFIERS
    }
    for item in files:
        file_name = str(item["file"])
        text = bodies[file_name].decode("utf-8", errors="replace")
        for identifier in ANALYSIS_IDENTIFIERS:
            count = text.count(identifier)
            if count:
                identifiers[identifier].append({"file": file_name, "count": count})
    return {
        "format": "dorm-static-script-analysis-v1",
        "identifiers": identifiers,
        "notes": [
            "仅统计静态 JavaScript 中的标识符出现次数，不包含运行时会话值。",
            "请将本 ZIP 保存到本地，供后续离线分析使用。",
        ],
    }


def collect_dorm_static_scripts(
    interface_ip: str,
    *,
    capture_dir: Path = CAPTURE_DIR,
    output_root: Path = SURVEY_DIR,
    fetcher: Callable[[str, str], ScriptDownload] | None = None,
) -> DormScriptSurveyResult:
    interface_ip = _validated_interface_ip(interface_ip)
    capture_path, script_paths = find_latest_complete_capture(capture_dir)
    fetch = fetcher or _fetch_script_http
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    survey_name = f"survey-{stamp}-{secrets.token_hex(4)}"
    output_dir = output_root / survey_name
    scripts_dir = output_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=False)

    files: list[dict[str, object]] = []
    bodies: dict[str, bytes] = {}
    total_bytes = 0
    for index, path in enumerate(script_paths, start=1):
        download = fetch(path, interface_ip)
        if not isinstance(download, ScriptDownload):
            raise DormScriptSurveyError("静态脚本下载器返回了无效结果")
        media_type = download.content_type.split(";", 1)[0].strip().lower()
        if download.status != 200 or media_type not in SCRIPT_MEDIA_TYPES:
            raise DormScriptSurveyError("官方门户资源未返回可接受的 JavaScript")
        body = bytes(download.body)
        if not body or len(body) > MAX_SCRIPT_BYTES:
            raise DormScriptSurveyError("官方静态脚本为空或超过单文件大小上限")
        if body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            raise DormScriptSurveyError("官方门户返回了 HTML，而不是静态 JavaScript")
        total_bytes += len(body)
        if total_bytes > MAX_TOTAL_SCRIPT_BYTES:
            raise DormScriptSurveyError("官方静态脚本总大小超过调查上限")
        digest = hashlib.sha256(body).hexdigest()
        file_name = _script_file_name(index, path, digest)
        (scripts_dir / file_name).write_bytes(body)
        bodies[file_name] = body
        files.append({
            "path": path,
            "file": file_name,
            "bytes": len(body),
            "sha256": digest,
            "content_type": media_type,
        })

    manifest = {
        "format": "dorm-static-script-survey-v1",
        "privacy_profile": "official-static-javascript-only-v1",
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "portal_origin": f"{PORTAL_SCHEME}://{PORTAL_HOST}",
        "source_capture": capture_path.name,
        "request_policy": {
            "method": "GET",
            "cookies_sent": False,
            "referer_sent": False,
            "redirects_followed": False,
            "bound_to_dorm_ethernet": True,
        },
        "script_count": len(files),
        "total_bytes": total_bytes,
        "files": files,
    }
    analysis = _analysis_for_scripts(files, bodies)
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "analysis.json").write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    archive_path = output_root / f"{survey_name}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(output_dir / "manifest.json", "manifest.json")
        archive.write(output_dir / "analysis.json", "analysis.json")
        for item in files:
            file_name = str(item["file"])
            archive.write(scripts_dir / file_name, f"scripts/{file_name}")
    return DormScriptSurveyResult(
        archive_path=archive_path,
        output_dir=output_dir,
        script_count=len(files),
        total_bytes=total_bytes,
        source_capture=capture_path.name,
    )
