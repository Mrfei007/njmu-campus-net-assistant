"""Build a shareable, source-free report from one completed dorm capture."""

from __future__ import annotations

import json
import re
import secrets
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import APP_DIR
from .dorm_observer import (
    INLINE_FEATURE_PATTERNS,
    MAX_INLINE_SOURCE_BYTES,
    MAX_INLINE_TOKEN_COUNT,
    PORTAL_HOST,
    PORTAL_SCHEME,
    SAFE_JS_IDENTIFIERS,
    SAFE_JS_STRING_LITERALS,
    SAFE_SMALL_NUMBERS,
    _safe_field_name,
    _safe_path,
)


INLINE_SURVEY_DIR = APP_DIR / "diagnostics" / "dorm-inline-wrapper-survey"
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_CAPTURE_RECORDS = 5000
MAX_ANALYSES = 16
SAFE_PUNCTUATION_TOKENS = {
    "{", "}", "[", "]", "(", ")", ".", ",", ";", ":", "?", "+", "-", "*", "/", "%",
    "<", ">", "=", "!", "&", "|", "^", "~", "===", "!==", ">>>", "**=", "=>", "==", "!=",
    "<=", ">=", "++", "--", "&&", "||", "??", "?.", "+=", "-=", "*=", "/=", "%=", "<<",
    ">>", "**", "&=", "|=", "^=",
}


@dataclass(frozen=True)
class DormInlineSurveyResult:
    archive_path: Path
    output_dir: Path
    analysis_count: int
    source_capture: str


def _safe_function_name(value: object) -> str | None:
    name = str(value or "")
    if name == "(anonymous)" or re.fullmatch(r"[$A-Za-z_][$A-Za-z0-9_]{0,63}", name):
        return name
    return None


def _safe_int(value: object, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return value


def _safe_tokens(value: object, *, function_name: str, query_fields: list[str]) -> list[str] | None:
    if not isinstance(value, list) or len(value) > MAX_INLINE_TOKEN_COUNT:
        return None
    allowed_identifiers = SAFE_JS_IDENTIFIERS | set(query_fields) | {function_name}
    allowed_strings = SAFE_JS_STRING_LITERALS | set(query_fields)
    tokens: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 80:
            return None
        allowed = (
            item in SAFE_PUNCTUATION_TOKENS
            or item in allowed_identifiers
            or item in SAFE_SMALL_NUMBERS
            or item == "num"
            or re.fullmatch(r"id[1-9][0-9]{0,3}", item) is not None
            or item in {"str:empty", "str:1-7", "str:8-15", "str:16-31", "str:32-63", "str:64+"}
            or (item.startswith("str:") and item[4:] in allowed_strings)
        )
        if not allowed:
            return None
        tokens.append(item)
    return tokens


def _validated_analysis(record: dict) -> dict[str, object] | None:
    script_id = str(record.get("script_id") or "")
    function_name = _safe_function_name(record.get("function"))
    line = _safe_int(record.get("line"), 10_000_000)
    column = _safe_int(record.get("column"), 10_000_000)
    if not re.fullmatch(r"[0-9a-f]{16}", script_id) or function_name is None or line is None or column is None:
        return None

    target = record.get("target") if isinstance(record.get("target"), dict) else {}
    raw_query_fields = target.get("query_fields") if isinstance(target.get("query_fields"), list) else []
    query_fields = [
        name for item in raw_query_fields[:64]
        if (name := _safe_field_name(item)) is not None
    ]
    path = str(target.get("path") or "")
    if (
        target.get("scheme") != PORTAL_SCHEME
        or target.get("host") != PORTAL_HOST
        or not path.startswith(("/eportal/", "/cas-sso/"))
        or _safe_path(path) != path
    ):
        return None

    source_meta = record.get("source_meta") if isinstance(record.get("source_meta"), dict) else {}
    source_bytes = _safe_int(source_meta.get("bytes"), MAX_INLINE_SOURCE_BYTES)
    source_sha256 = str(source_meta.get("sha256") or "")
    window_start = _safe_int(source_meta.get("window_start"), MAX_INLINE_SOURCE_BYTES)
    window_end = _safe_int(source_meta.get("window_end"), MAX_INLINE_SOURCE_BYTES)
    if (
        source_bytes is None
        or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
        or window_start is None
        or window_end is None
        or window_start > window_end
    ):
        return None

    raw_features = record.get("features") if isinstance(record.get("features"), dict) else {}
    features: dict[str, int] = {}
    for name in INLINE_FEATURE_PATTERNS:
        count = _safe_int(raw_features.get(name, 0), 999)
        if count is None:
            return None
        features[name] = count

    token_window = record.get("token_window") if isinstance(record.get("token_window"), dict) else {}
    if token_window.get("format") != "redacted-js-token-window-v1":
        return None
    tokens = _safe_tokens(
        token_window.get("tokens"),
        function_name=function_name,
        query_fields=query_fields,
    )
    if tokens is None:
        return None
    return {
        "script_id": script_id,
        "function": function_name,
        "line": line,
        "column": column,
        "target": {
            "scheme": PORTAL_SCHEME,
            "host": PORTAL_HOST,
            "path": path,
            "query_fields": query_fields,
        },
        "source_meta": {
            "bytes": source_bytes,
            "sha256": source_sha256,
            "window_start": window_start,
            "window_end": window_end,
        },
        "features": features,
        "token_window": {
            "format": "redacted-js-token-window-v1",
            "tokens": tokens,
        },
    }


def _read_completed_capture(capture_path: Path) -> list[dict[str, object]] | None:
    try:
        if not capture_path.is_file() or capture_path.stat().st_size > MAX_CAPTURE_BYTES:
            return None
        lines = capture_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if len(lines) > MAX_CAPTURE_RECORDS:
        return None
    capture_id = ""
    started = False
    complete = False
    analyses: list[dict[str, object]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None
        event_name = record.get("event")
        if event_name == "capture-started":
            capture_id = str(record.get("capture_id") or "")
            started = (
                bool(capture_id)
                and record.get("privacy_profile") == "metadata-only-v2"
                and record.get("portal_host") == PORTAL_HOST
            )
        elif event_name == "inline-wrapper-analysis" and started:
            if record.get("capture_id") != capture_id:
                return None
            analysis = _validated_analysis(record)
            if analysis is not None and len(analyses) < MAX_ANALYSES:
                analyses.append(analysis)
        elif event_name == "capture-stopped" and started:
            complete = record.get("capture_id") == capture_id and record.get("complete") is True
    return analyses if started and complete and analyses else None


def build_inline_wrapper_survey(
    capture_path: Path,
    *,
    output_root: Path = INLINE_SURVEY_DIR,
) -> DormInlineSurveyResult | None:
    analyses = _read_completed_capture(capture_path)
    if not analyses:
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    survey_name = f"inline-wrapper-{stamp}-{secrets.token_hex(4)}"
    output_dir = output_root / survey_name
    output_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "format": "dorm-inline-wrapper-survey-v1",
        "privacy_profile": "redacted-token-window-only-v1",
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "portal_origin": f"{PORTAL_SCHEME}://{PORTAL_HOST}",
        "source_capture": capture_path.name,
        "analysis_count": len(analyses),
        "raw_source_included": False,
        "observer_capture_included": False,
        "notes": [
            "内联脚本原文只在浏览器观察期间短暂驻留内存，本调查包不包含原文。",
            "任意字符串值和非白名单标识符已替换为形态或局部占位符。",
        ],
    }
    analysis_payload = {
        "format": "dorm-inline-wrapper-analysis-v1",
        "analyses": analyses,
    }
    manifest_path = output_dir / "manifest.json"
    analysis_path = output_dir / "analysis.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    analysis_path.write_text(json.dumps(analysis_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    archive_path = output_root / f"{survey_name}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(manifest_path, "manifest.json")
        archive.write(analysis_path, "analysis.json")
    return DormInlineSurveyResult(
        archive_path=archive_path,
        output_dir=output_dir,
        analysis_count=len(analyses),
        source_capture=capture_path.name,
    )
