"""Privacy-bounded CDP observer for the NJMU dorm Ethernet portal.

The observer is opt-in and records protocol metadata only. It never writes a
complete URL, request body, cookie, credential, session value, ticket or key.
Sensitive values may receive an ephemeral HMAC label so equality can be
checked within one capture; the random HMAC key is never persisted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

from .config import APP_DIR
PORTAL_HOST = "202.195.176.60"
PORTAL_SCHEME = "http"
CAPTURE_DIR = APP_DIR / "diagnostics" / "dorm-protocol-observer"
MAX_RESPONSE_BODY_BYTES = 1024 * 1024
MAX_INLINE_SOURCE_BYTES = 1024 * 1024
MAX_INLINE_TOKEN_COUNT = 384
INLINE_WINDOW_BEFORE = 4096
INLINE_WINDOW_AFTER = 8192
MAX_RECORDS = 1200
MAX_TRACKED_REQUESTS = 256
KNOWN_PATHS = {
    "/portal/portal-main",
    "/portal/entry",
    "/portal/entry/pc/authenticate",
    "/portal/entry/pc/serviceSelection",
    "/portal/entry/pc/finish",
    "/portal/assets/auth-success.html",
    "/cas-sso/login",
    "/eportal/workFlow/getCurrentNode",
    "/eportal/network/serviceSelection",
    "/eportal/network/serviceLogin",
}
TRACKED_VALUE_FIELDS = {"sessionid", "flowsessionid", "flowkey", "ttbyz9wp"}
SAFE_EXACT_FORM_FIELDS = {"_eventid", "type"}
SAFE_EMPTY_FORM_FIELDS = {"geolocation", "captcha_code", "captcha_payload"}
SAFE_HEADER_NAMES = {
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "host",
    "isportal",
    "origin",
    "referer",
    "user-agent",
}
IDENTIFIER_NAMES = (
    "sessionId",
    "flowSessionId",
    "flowKey",
    "ttbYz9WP",
    "isPortal",
    "accept-language",
    "captcha_payload",
)
INLINE_FEATURE_PATTERNS = {
    "date_now": r"\bDate\s*\.\s*now\s*\(",
    "new_date": r"\bnew\s+Date\s*\(",
    "math_random": r"\bMath\s*\.\s*random\s*\(",
    "crypto_random": r"\bcrypto\s*\.\s*getRandomValues\s*\(",
    "performance_now": r"\bperformance\s*\.\s*now\s*\(",
    "document_cookie": r"\bdocument\s*\.\s*cookie\b",
    "url_search_params": r"\bURLSearchParams\b",
    "encode_uri_component": r"\bencodeURIComponent\s*\(",
    "decode_uri_component": r"\bdecodeURIComponent\s*\(",
    "xml_http_request": r"\bXMLHttpRequest\b",
    "fetch": r"\bfetch\s*\(",
    "set_request_header": r"\bsetRequestHeader\s*\(",
    "local_storage": r"\blocalStorage\b",
    "session_storage": r"\bsessionStorage\b",
    "btoa": r"\bbtoa\s*\(",
    "atob": r"\batob\s*\(",
}
SAFE_JS_IDENTIFIERS = {
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "crypto", "Date", "decodeURIComponent", "default", "delete", "document", "else",
    "encodeURIComponent", "false", "fetch", "finally", "for", "function", "getRandomValues",
    "if", "in", "instanceof", "let", "localStorage", "Math", "new", "now", "null", "open",
    "performance", "random", "return", "send", "sessionStorage", "setRequestHeader", "switch",
    "this", "throw", "true", "try", "typeof", "undefined", "URL", "URLSearchParams", "var",
    "void", "while", "with", "XMLHttpRequest", "yield", "cookie", "btoa", "atob",
}
SAFE_JS_STRING_LITERALS = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
    "application/json", "Content-Type", "isPortal",
}
SAFE_SMALL_NUMBERS = {"0", "1", "2", "8", "16", "32", "64", "128", "256", "512", "1024"}
MULTI_CHAR_OPERATORS = (
    "===", "!==", ">>>", "**=", "=>", "==", "!=", "<=", ">=", "++", "--", "&&", "||",
    "??", "?.", "+=", "-=", "*=", "/=", "%=", "<<", ">>", "**", "&=", "|=", "^=",
)


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _safe_text(value: object, limit: int = 128) -> str:
    text = str(value or "")
    text = "".join(char for char in text if char.isprintable() and char not in "\r\n")
    return text[:limit]


def _safe_path(path: str) -> str:
    safe_segments: list[str] = []
    for encoded in path.split("/"):
        segment = urllib.parse.unquote(encoded)
        stem = segment.rsplit(".", 1)[0]
        if (
            len(segment) > 80
            or re.fullmatch(r"[A-Za-z0-9_\-]{24,}", stem or "")
        ):
            safe_segments.append("[dynamic]")
        else:
            safe_segments.append(_safe_text(segment, 80))
    return "/".join(safe_segments)[:256] or "/"


def _safe_field_name(value: object) -> str | None:
    name = str(value or "")
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]{0,63}", name) else None


def _safe_js_name(value: object) -> str:
    name = str(value or "")
    if re.fullmatch(r"[$A-Za-z_][$A-Za-z0-9_]{0,63}", name):
        return name
    return "(anonymous)"


def _bounded_position(value: object) -> int:
    try:
        return min(max(int(value or 0), 0), 10_000_000)
    except (TypeError, ValueError, OverflowError):
        return 0


def _source_offset(source: str, line: int, column: int, function_name: str) -> int:
    lines = source.splitlines(keepends=True)
    candidates: list[int] = []
    for line_index in {line, max(0, line - 1)}:
        if line_index < len(lines):
            candidates.append(min(sum(len(item) for item in lines[:line_index]) + column, len(source)))
    if not candidates:
        candidates = [min(column, len(source))]
    if function_name and function_name != "(anonymous)":
        occurrences: list[int] = []
        start = 0
        while len(occurrences) < 128:
            found = source.find(function_name, start)
            if found < 0:
                break
            occurrences.append(found)
            start = found + max(1, len(function_name))
        if occurrences:
            return min(occurrences, key=lambda item: min(abs(item - candidate) for candidate in candidates))
    return candidates[0]


def _string_shape(length: int) -> str:
    if length == 0:
        return "empty"
    if length <= 7:
        return "1-7"
    if length <= 15:
        return "8-15"
    if length <= 31:
        return "16-31"
    if length <= 63:
        return "32-63"
    return "64+"


def _redacted_js_tokens(
    source: str,
    *,
    function_name: str,
    query_fields: list[str],
    limit: int = MAX_INLINE_TOKEN_COUNT,
) -> list[str]:
    safe_strings = SAFE_JS_STRING_LITERALS | set(query_fields)
    safe_identifiers = SAFE_JS_IDENTIFIERS | set(query_fields)
    if function_name != "(anonymous)":
        safe_identifiers.add(function_name)
    identifiers: dict[str, str] = {}
    tokens: list[str] = []
    index = 0
    length = len(source)

    def append(token: str) -> None:
        if len(tokens) < limit:
            tokens.append(token[:80])

    while index < length and len(tokens) < limit:
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            index = length if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if char in {"'", '"', "`"}:
            quote = char
            cursor = index + 1
            escaped = False
            while cursor < length:
                current = source[cursor]
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    break
                cursor += 1
            raw_value = source[index + 1:cursor]
            if "\\" not in raw_value and raw_value in safe_strings:
                append(f"str:{raw_value}")
            else:
                append(f"str:{_string_shape(len(raw_value))}")
            index = min(cursor + 1, length)
            continue
        identifier = re.match(r"[$A-Za-z_][$A-Za-z0-9_]*", source[index:])
        if identifier:
            value = identifier.group(0)
            if value in safe_identifiers:
                append(value)
            else:
                placeholder = identifiers.setdefault(value, f"id{len(identifiers) + 1}")
                append(placeholder)
            index += len(value)
            continue
        number = re.match(r"(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)", source[index:])
        if number:
            value = number.group(0)
            append(value if value in SAFE_SMALL_NUMBERS else "num")
            index += len(value)
            continue
        operator = next((item for item in MULTI_CHAR_OPERATORS if source.startswith(item, index)), None)
        if operator:
            append(operator)
            index += len(operator)
            continue
        if char in "{}[]().,;:?+-*/%<>=!&|^~":
            append(char)
        index += 1
    return tokens


def _inline_source_analysis(source: str, context: dict[str, object]) -> dict[str, object]:
    function_name = _safe_js_name(context.get("function"))
    line = _bounded_position(context.get("line"))
    column = _bounded_position(context.get("column"))
    target = context.get("target") if isinstance(context.get("target"), dict) else {}
    query_fields = [
        name for item in target.get("query_fields", [])[:64]
        if (name := _safe_field_name(item)) is not None
    ] if isinstance(target.get("query_fields"), list) else []
    offset = _source_offset(source, line, column, function_name)
    start = max(0, offset - INLINE_WINDOW_BEFORE)
    end = min(len(source), offset + INLINE_WINDOW_AFTER)
    window = source[start:end]
    features = {
        name: min(len(re.findall(pattern, source)), 999)
        for name, pattern in INLINE_FEATURE_PATTERNS.items()
    }
    return {
        "script_id": str(context.get("script_tag") or "")[:16],
        "function": function_name,
        "line": line,
        "column": column,
        "target": {
            "scheme": PORTAL_SCHEME,
            "host": PORTAL_HOST,
            "path": _safe_path(str(target.get("path") or "/")),
            "query_fields": query_fields,
        },
        "source_meta": {
            "bytes": len(source.encode("utf-8", errors="replace")),
            "sha256": hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest(),
            "window_start": start,
            "window_end": end,
        },
        "features": features,
        "token_window": {
            "format": "redacted-js-token-window-v1",
            "tokens": _redacted_js_tokens(
                window,
                function_name=function_name,
                query_fields=query_fields,
            ),
        },
    }


class DormCaptureSanitizer:
    def __init__(self, tag_key: bytes | None = None) -> None:
        self._tag_key = tag_key or secrets.token_bytes(32)

    def tag(self, value: object) -> str:
        payload = str(value).encode("utf-8", errors="replace")
        return hmac.new(self._tag_key, payload, hashlib.sha256).hexdigest()[:16]

    def url(self, value: object) -> dict | None:
        raw = str(value or "")
        if raw.startswith("/"):
            raw = f"{PORTAL_SCHEME}://{PORTAL_HOST}{raw}"
        try:
            parsed = urllib.parse.urlsplit(raw)
            invalid_target = (
                parsed.scheme.lower() != PORTAL_SCHEME
                or (parsed.hostname or "").lower() != PORTAL_HOST
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
            )
        except ValueError:
            return None
        if invalid_target:
            return None
        path = parsed.path or "/"
        if not self.path_allowed(path):
            return None
        try:
            query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        except ValueError:
            query = []
        record: dict[str, object] = {
            "scheme": PORTAL_SCHEME,
            "host": PORTAL_HOST,
            "path": _safe_path(path),
            "query_fields": sorted({name for key, _ in query if (name := _safe_field_name(key))})[:64],
        }
        tags: dict[str, list[str]] = {}
        for key, item in query:
            safe_key = _safe_field_name(key)
            if safe_key and key.lower() in TRACKED_VALUE_FIELDS and item:
                tags.setdefault(safe_key, []).append(self.tag(item))
        if tags:
            record["value_tags"] = tags
        return record

    @staticmethod
    def path_allowed(path: str) -> bool:
        return (
            path in KNOWN_PATHS
            or path.startswith("/portal/")
            or path.startswith("/eportal/")
            or path.startswith("/cas-sso/")
        )

    def headers(self, headers: object) -> dict[str, object]:
        if not isinstance(headers, dict):
            return {"names": []}
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        names = sorted(name for name in normalized if name in SAFE_HEADER_NAMES)
        safe_values: dict[str, object] = {}
        sensitive_presence = sorted(
            name for name in ("authorization", "cookie", "set-cookie") if name in normalized
        )
        content_type = normalized.get("content-type", "")
        if content_type:
            safe_values["content-type"] = _safe_text(content_type, 160)
        accept_language = normalized.get("accept-language", "")
        if accept_language and re.fullmatch(r"[A-Za-z0-9,;=.\- ]{1,128}", accept_language):
            safe_values["accept-language"] = accept_language
        is_portal = normalized.get("isportal", "")
        if is_portal and re.fullmatch(r"[A-Za-z0-9_.\-]{1,32}", is_portal):
            safe_values["isPortal"] = is_portal
        origin = normalized.get("origin", "")
        if origin.rstrip("/").lower() == f"{PORTAL_SCHEME}://{PORTAL_HOST}":
            safe_values["origin"] = f"{PORTAL_SCHEME}://{PORTAL_HOST}"
        referer = self.url(normalized.get("referer", ""))
        if referer is not None:
            safe_values["referer"] = referer
        cookie_names: list[str] = []
        cookie_header = normalized.get("cookie", "")
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", name):
                cookie_names.append(name)
        record: dict[str, object] = {"names": names}
        if safe_values:
            record["safe_values"] = safe_values
        if sensitive_presence:
            record["sensitive_presence"] = sensitive_presence
        if cookie_names:
            record["cookie_names"] = sorted(set(cookie_names))[:32]
        return record

    def body(self, post_data: object, content_type: str = "") -> dict[str, object] | None:
        if not isinstance(post_data, str) or not post_data:
            return None
        media_type = content_type.split(";", 1)[0].strip().lower()
        values: dict[str, object]
        encoding: str
        try:
            if media_type == "application/json" or post_data.lstrip().startswith("{"):
                parsed = json.loads(post_data)
                if not isinstance(parsed, dict):
                    return {"encoding": "json", "shape": type(parsed).__name__}
                values = parsed
                encoding = "json"
            else:
                pairs = urllib.parse.parse_qsl(post_data, keep_blank_values=True)
                values = {}
                for key, value in pairs:
                    values.setdefault(key, value)
                encoding = "form"
        except (ValueError, TypeError, json.JSONDecodeError):
            return {"encoding": "unknown", "parse_error": True}
        fields = sorted(
            name for key in values if (name := _safe_field_name(key))
        )[:128]
        record: dict[str, object] = {"encoding": encoding, "fields": fields}
        exact_values: dict[str, str] = {}
        empty_fields: list[str] = []
        tags: dict[str, str] = {}
        for key, item in values.items():
            safe_key = _safe_field_name(key)
            if safe_key is None:
                continue
            lowered = safe_key.lower()
            text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, separators=(",", ":"))
            if lowered in SAFE_EXACT_FORM_FIELDS and re.fullmatch(r"[A-Za-z0-9_.\-]{0,64}", text):
                exact_values[safe_key] = text
            if lowered in SAFE_EMPTY_FORM_FIELDS and text == "":
                empty_fields.append(safe_key)
            if lowered in TRACKED_VALUE_FIELDS and text:
                tags[safe_key] = self.tag(text)
        if exact_values:
            record["safe_values"] = exact_values
        if empty_fields:
            record["empty_fields"] = sorted(empty_fields)
        if tags:
            record["value_tags"] = tags
        return record

    def initiator(
        self,
        value: object,
        script_urls: dict[str, dict[str, object]] | None = None,
    ) -> dict[str, object] | None:
        if not isinstance(value, dict):
            return None
        record: dict[str, object] = {"type": _safe_text(value.get("type"), 32)}
        stack = value.get("stack")
        frames = stack.get("callFrames", []) if isinstance(stack, dict) else []
        safe_frames: list[dict[str, object]] = []
        for frame in frames[:8]:
            if not isinstance(frame, dict):
                continue
            item: dict[str, object] = {
                "function": _safe_text(frame.get("functionName") or "(anonymous)"),
                "line": int(frame.get("lineNumber") or 0),
                "column": int(frame.get("columnNumber") or 0),
            }
            script_id = str(frame.get("scriptId") or "")
            if script_id:
                item["script_id"] = self.tag(script_id)
            script_url = self.url(frame.get("url"))
            if script_url is None and script_id and script_urls:
                script_url = script_urls.get(script_id)
            if script_url is not None:
                item["script"] = script_url
            elif not frame.get("url"):
                item["script_kind"] = "inline-or-anonymous"
            safe_frames.append(item)
        if safe_frames:
            record["frames"] = safe_frames
        return record

    def response_body(self, body: str, mime_type: str) -> dict[str, object]:
        encoded = body.encode("utf-8", errors="replace")
        record: dict[str, object] = {
            "bytes": len(encoded),
            "body_tag": self.tag(body),
        }
        lowered_mime = (mime_type or "").lower()
        if "json" in lowered_mime or body.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                record["parse_error"] = True
                return record
            fields: list[str] = []
            tags: dict[str, list[str]] = {}

            def walk(value: object, prefix: str = "", depth: int = 0) -> None:
                if depth > 6 or len(fields) >= 160:
                    return
                if isinstance(value, dict):
                    for key, item in value.items():
                        name = _safe_field_name(key)
                        if name is None:
                            continue
                        path = f"{prefix}.{name}" if prefix else name
                        fields.append(path[:256])
                        if name.lower() in TRACKED_VALUE_FIELDS and isinstance(item, (str, int)):
                            tags.setdefault(path[:256], []).append(self.tag(item))
                        walk(item, path, depth + 1)
                elif isinstance(value, list):
                    for item in value[:16]:
                        walk(item, f"{prefix}[]", depth + 1)

            walk(parsed)
            record["field_paths"] = sorted(set(fields))[:160]
            if tags:
                record["value_tags"] = tags
            return record
        identifiers = [name for name in IDENTIFIER_NAMES if name in body]
        if identifiers:
            record["observed_identifiers"] = identifiers
        return record


class DormProtocolRecorder:
    def __init__(self, output_path: Path, *, sanitizer: DormCaptureSanitizer | None = None, lightweight: bool = False) -> None:
        self.output_path = output_path
        self.lightweight = lightweight
        self.sanitizer = sanitizer or DormCaptureSanitizer()
        self.capture_id = secrets.token_hex(8)
        self._lock = threading.Lock()
        self._record_count = 0
        self._requests: dict[str, dict[str, object]] = {}
        self._script_urls: dict[str, dict[str, object]] = {}
        self._requested_inline_scripts: set[str] = set()

    @property
    def public_name(self) -> str:
        return self.output_path.name

    def write(self, event_name: str, **fields: object) -> None:
        with self._lock:
            if self._record_count >= MAX_RECORDS:
                return
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "time": _now(),
                "event": event_name,
                "capture_id": self.capture_id,
                **fields,
            }
            with self.output_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            self._record_count += 1

    def handle_event(self, message: dict) -> list[tuple[str, dict, dict]]:
        method = str(message.get("method") or "")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        commands: list[tuple[str, dict, dict]] = []
        if method == "Network.requestWillBeSent":
            request = params.get("request") if isinstance(params.get("request"), dict) else {}
            safe_url = self.sanitizer.url(request.get("url"))
            if safe_url is None:
                return commands
            request_id = str(params.get("requestId") or "")
            headers = self.sanitizer.headers(request.get("headers"))
            content_type = str(
                ((headers.get("safe_values") or {}).get("content-type") if isinstance(headers, dict) else "")
                or ""
            )
            body = self.sanitizer.body(request.get("postData"), content_type)
            self._requests[request_id] = {
                "url": safe_url,
                "mime_type": "",
                "status": None,
                "started": time.monotonic(),
                "terminal": False,
            }
            while len(self._requests) > MAX_TRACKED_REQUESTS:
                evicted_id = next(iter(self._requests))
                evicted = self._requests.pop(evicted_id)
                if not evicted.get("terminal"):
                    self.write("request-tracking-evicted", request_id=self.sanitizer.tag(evicted_id), target=evicted.get("url"))
            fields: dict[str, object] = {
                "request_id": self.sanitizer.tag(request_id),
                "method": _safe_text(request.get("method"), 16).upper(),
                "target": safe_url,
                "headers": headers,
            }
            initiator = self.sanitizer.initiator(params.get("initiator"), self._script_urls)
            if initiator:
                fields["initiator"] = initiator
            if body:
                fields["body"] = body
            redirect = params.get("redirectResponse")
            if isinstance(redirect, dict):
                fields["redirect_from_status"] = int(redirect.get("status") or 0)
            self.write("request", **fields)
            path = str(safe_url.get("path") or "")
            query_fields = safe_url.get("query_fields")
            if (
                not self.lightweight
                and path.startswith(("/eportal/", "/cas-sso/"))
                and isinstance(query_fields, list)
                and "ttbYz9WP" in query_fields
            ):
                raw_initiator = params.get("initiator")
                stack = raw_initiator.get("stack") if isinstance(raw_initiator, dict) else None
                frames = stack.get("callFrames", []) if isinstance(stack, dict) else []
                for frame in frames[:8]:
                    if not isinstance(frame, dict) or frame.get("url"):
                        continue
                    script_id = str(frame.get("scriptId") or "")
                    if (
                        not script_id
                        or script_id in self._script_urls
                        or script_id in self._requested_inline_scripts
                    ):
                        continue
                    self._requested_inline_scripts.add(script_id)
                    commands.append((
                        "Debugger.getScriptSource",
                        {"scriptId": script_id},
                        {
                            "kind": "inline-wrapper-source",
                            "script_id": script_id,
                            "script_tag": self.sanitizer.tag(script_id),
                            "function": _safe_js_name(frame.get("functionName")),
                            "line": _bounded_position(frame.get("lineNumber")),
                            "column": _bounded_position(frame.get("columnNumber")),
                            "target": safe_url,
                        },
                    ))
                    break
        elif method == "Network.requestWillBeSentExtraInfo":
            request_id = str(params.get("requestId") or "")
            if request_id in self._requests:
                self.write(
                    "request-extra",
                    request_id=self.sanitizer.tag(request_id),
                    headers=self.sanitizer.headers(params.get("headers")),
                )
        elif method == "Network.responseReceived":
            response = params.get("response") if isinstance(params.get("response"), dict) else {}
            safe_url = self.sanitizer.url(response.get("url"))
            if safe_url is None:
                return commands
            request_id = str(params.get("requestId") or "")
            tracked = self._requests.setdefault(request_id, {"url": safe_url})
            tracked["mime_type"] = _safe_text(response.get("mimeType"), 128)
            tracked["status"] = int(response.get("status") or 0)
            self.write(
                "response",
                request_id=self.sanitizer.tag(request_id),
                target=safe_url,
                status=tracked["status"],
                mime_type=tracked["mime_type"],
                headers=self.sanitizer.headers(response.get("headers")),
            )
        elif method == "Network.responseReceivedExtraInfo":
            request_id = str(params.get("requestId") or "")
            if request_id in self._requests:
                headers = params.get("headers") if isinstance(params.get("headers"), dict) else {}
                location = self.sanitizer.url(
                    next((value for key, value in headers.items() if str(key).lower() == "location"), "")
                )
                fields = {
                    "request_id": self.sanitizer.tag(request_id),
                    "status": int(params.get("statusCode") or 0),
                    "headers": self.sanitizer.headers(headers),
                }
                if location is not None:
                    fields["location"] = location
                self.write("response-extra", **fields)
        elif method == "Network.loadingFailed":
            request_id = str(params.get("requestId") or "")
            tracked = self._requests.get(request_id)
            if tracked:
                tracked["terminal"] = True
                # Never copy free-form browser errors, which may contain URLs.
                raw_error = str(params.get("errorText") or "")
                error_code = re.search(r"\bnet::ERR_[A-Z0-9_]+\b", raw_error)
                blocked = str(params.get("blockedReason") or "")
                self.write(
                    "request-failed", request_id=self.sanitizer.tag(request_id),
                    target=tracked.get("url"),
                    error_code=error_code.group(0) if error_code else "unclassified",
                    canceled=bool(params.get("canceled")),
                    blocked_reason=blocked if blocked in {
                        "other", "csp", "mixed-content", "origin", "inspector", "subresource-filter",
                        "content-type", "coep-frame-resource-needs-coep-header", "coop-sandboxed-iframe-cannot-navigate-to-coop-page",
                        "corp-not-same-origin", "corp-not-same-origin-after-defaulted-to-same-origin-by-coep", "corp-not-same-site",
                    } else ("unclassified" if blocked else ""),
                    cors_error_present=bool(params.get("corsErrorStatus")),
                    elapsed_seconds=round(max(0.0, time.monotonic() - float(tracked.get("started", time.monotonic()))), 3),
                )
        elif method == "Network.loadingFinished":
            request_id = str(params.get("requestId") or "")
            tracked = self._requests.get(request_id)
            size = int(params.get("encodedDataLength") or 0)
            if tracked:
                tracked["terminal"] = True
                self.write("request-finished", request_id=self.sanitizer.tag(request_id),
                           target=tracked.get("url"), encoded_bytes=max(0, size),
                           elapsed_seconds=round(max(0.0, time.monotonic() - float(tracked.get("started", time.monotonic()))), 3))
            if not self.lightweight and tracked and 0 <= size <= MAX_RESPONSE_BODY_BYTES:
                commands.append((
                    "Network.getResponseBody",
                    {"requestId": request_id},
                    {"request_id": request_id},
                ))
        elif method == "Page.frameNavigated":
            frame = params.get("frame") if isinstance(params.get("frame"), dict) else {}
            safe_url = self.sanitizer.url(frame.get("url"))
            if safe_url is not None:
                self.write(
                    "frame-navigated",
                    target=safe_url,
                    top_level=not bool(frame.get("parentId")),
                )
        elif method == "Debugger.scriptParsed":
            script_id = str(params.get("scriptId") or "")
            safe_url = self.sanitizer.url(params.get("url"))
            path = str((safe_url or {}).get("path") or "")
            if script_id and safe_url is not None and path.startswith("/portal/") and path.endswith(".js"):
                self._script_urls[script_id] = safe_url
                self.write(
                    "script-mapped",
                    script_id=self.sanitizer.tag(script_id),
                    target=safe_url,
                )
        return commands

    def record_pending(self) -> None:
        """Incomplete at capture end is not evidence of a network timeout."""
        for request_id, tracked in list(self._requests.items()):
            if not tracked.get("terminal"):
                self.write("request-pending-at-stop", request_id=self.sanitizer.tag(request_id),
                           target=tracked.get("url"), status=tracked.get("status"),
                           elapsed_seconds=round(max(0.0, time.monotonic() - float(tracked.get("started", time.monotonic()))), 3))

    def handle_command_response(self, context: dict, message: dict) -> None:
        if context.get("kind") == "inline-wrapper-source":
            result = message.get("result") if isinstance(message.get("result"), dict) else {}
            source = result.get("scriptSource")
            if not isinstance(source, str):
                self.write(
                    "inline-wrapper-skipped",
                    script_id=str(context.get("script_tag") or "")[:16],
                    reason="source-unavailable",
                )
                return
            source_size = len(source.encode("utf-8", errors="replace"))
            if source_size > MAX_INLINE_SOURCE_BYTES:
                self.write(
                    "inline-wrapper-skipped",
                    script_id=str(context.get("script_tag") or "")[:16],
                    reason="source-too-large",
                    source_bytes=source_size,
                )
                return
            self.write("inline-wrapper-analysis", **_inline_source_analysis(source, context))
            return
        request_id = str(context.get("request_id") or "")
        tracked = self._requests.get(request_id)
        result = message.get("result") if isinstance(message.get("result"), dict) else {}
        if not tracked or "body" not in result:
            return
        body = result.get("body")
        if not isinstance(body, str):
            return
        if result.get("base64Encoded"):
            try:
                decoded = base64.b64decode(body, validate=True)
                body = decoded.decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                return
        if len(body.encode("utf-8", errors="replace")) > MAX_RESPONSE_BODY_BYTES:
            return
        shape = self.sanitizer.response_body(body, str(tracked.get("mime_type") or ""))
        self.write(
            "response-shape",
            request_id=self.sanitizer.tag(request_id),
            target=tracked.get("url"),
            status=tracked.get("status"),
            shape=shape,
        )


class DormProtocolObserver:
    def __init__(self, websocket_url: str, *, output_dir: Path | None = None) -> None:
        directory = output_dir or CAPTURE_DIR
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"capture-{stamp}-{secrets.token_hex(4)}.jsonl"
        self.recorder = DormProtocolRecorder(directory / filename, lightweight=True)
        self.output_dir = directory
        self.websocket_url = websocket_url
        self._client = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._pending: dict[int, dict] = {}
        self._counter = 1000
        self._healthy = False
        self._stopped = False
        self.survey_archive_path: Path | None = None

    @property
    def public_name(self) -> str:
        return self.recorder.public_name

    @property
    def healthy(self) -> bool:
        return self._healthy and not self._stopped and self._thread is not None and self._thread.is_alive()

    def start(self) -> "DormProtocolObserver":
        self._prune()
        from .edge import Cdp

        client = Cdp(self.websocket_url)
        try:
            client.call_result("Network.enable")
            client.call_result("Page.enable")
        except Exception as error:
            try:
                client.close()
            finally:
                self.recorder.write("capture-error", error_type=type(error).__name__, phase="initialization")
            raise
        self._client = client
        self.recorder.write(
            "capture-started",
            privacy_profile="metadata-only-v2",
            observation_mode="lightweight-network-v1",
            debugger_enabled=False,
            response_body_reading=False,
            portal_host=PORTAL_HOST,
        )
        self._healthy = True
        self._thread = threading.Thread(target=self._run, name="DormProtocolObserver", daemon=True)
        self._thread.start()
        return self

    def _send(self, method: str, params: dict, context: dict) -> None:
        client = self._client
        if client is None:
            return
        with self._send_lock:
            self._counter += 1
            ident = self._counter
            self._pending[ident] = context
            client.socket.send(json.dumps({"id": ident, "method": method, "params": params}))

    def _run(self) -> None:
        client = self._client
        if client is None:
            return
        try:
            while not self._stop.is_set():
                try:
                    raw = client.socket.recv()
                except Exception as error:
                    if self._stop.is_set():
                        break
                    if type(error).__name__ in {"WebSocketTimeoutException", "TimeoutError"}:
                        continue
                    raise
                if raw in (None, "", b""):
                    self._healthy = False
                    if not self._stop.is_set():
                        self.recorder.write("capture-ended", reason="websocket-closed")
                    break
                try:
                    message = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                    self._healthy = False
                    if not self._stop.is_set():
                        self.recorder.write("capture-ended", reason="invalid-cdp-message")
                    break
                if not isinstance(message, dict):
                    self._healthy = False
                    if not self._stop.is_set():
                        self.recorder.write("capture-ended", reason="invalid-cdp-message")
                    break
                ident = message.get("id")
                if isinstance(ident, int) and ident in self._pending:
                    context = self._pending.pop(ident)
                    self.recorder.handle_command_response(context, message)
                    continue
                for method, params, context in self.recorder.handle_event(message):
                    self._send(method, params, context)
        except Exception as error:
            self._healthy = False
            self.recorder.write("capture-error", error_type=type(error).__name__)

    def stop(self, reason: str, *, complete: bool) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._stop.set()
        client = self._client
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._thread is None or not self._thread.is_alive():
            self.recorder.record_pending()
        else:
            self.recorder.write("capture-error", error_type="ObserverShutdownTimeout")
        self.recorder.write(
            "capture-stopped",
            reason=_safe_text(reason, 64),
            complete=bool(complete),
            records=self.recorder._record_count,
        )
        if complete and not self.recorder.lightweight:
            try:
                from .dorm_inline_survey import build_inline_wrapper_survey

                result = build_inline_wrapper_survey(self.recorder.output_path)
                if result is not None:
                    self.survey_archive_path = result.archive_path
                    self.recorder.write(
                        "inline-wrapper-survey-created",
                        archive_file=result.archive_path.name,
                        analysis_count=result.analysis_count,
                    )
                else:
                    self.recorder.write(
                        "inline-wrapper-survey-skipped",
                        reason="no-valid-inline-analysis",
                    )
            except Exception as error:
                self.recorder.write(
                    "inline-wrapper-survey-skipped",
                    reason="export-failed",
                    error_type=type(error).__name__,
                )

    def _prune(self) -> None:
        cutoff = time.time() - 7 * 24 * 60 * 60
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            for path in self.output_dir.glob("capture-*.jsonl"):
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
        except OSError:
            pass
