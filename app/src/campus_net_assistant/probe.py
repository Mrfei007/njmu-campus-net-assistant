from __future__ import annotations

import subprocess
from dataclasses import dataclass, asdict


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def _curl_base(interface_ip: str) -> list[str]:
    return [
        "curl.exe",
        "--noproxy",
        "*",
        "--interface",
        interface_ip,
        "--connect-timeout",
        "8",
        "--max-time",
        "12",
        "-sS",
    ]


def internet_probe(interface_ip: str, url: str, success_text: str) -> bool:
    try:
        output = subprocess.check_output(
            [*_curl_base(interface_ip), url],
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        return output.strip() == success_text
    except (OSError, subprocess.SubprocessError):
        return False


def http_status_probe(interface_ip: str, url: str, expected_status: int = 204) -> bool:
    """Probe a fixed-status endpoint without following captive-portal redirects."""
    try:
        output = subprocess.check_output(
            [*_curl_base(interface_ip), "-o", "NUL", "-w", "%{http_code}", url],
            text=True,
            encoding="ascii",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
        return output.strip() == str(expected_status)
    except (OSError, subprocess.SubprocessError):
        return False


def connectivity_probe(
    interface_ip: str,
    primary_url: str,
    primary_success_text: str,
    secondary_url: str,
) -> tuple[bool, str]:
    """Validate internet access using independent Microsoft and Android targets."""
    if internet_probe(interface_ip, primary_url, primary_success_text):
        return True, "microsoft-connect-test"
    if secondary_url and http_status_probe(interface_ip, secondary_url, 204):
        return True, "android-generate-204"
    return False, "all-connectivity-probes-failed"


@dataclass(frozen=True)
class ProbeResult:
    success: bool
    source: str
    reason: str
    attempts: tuple[dict[str, object], ...] = ()

    def public_dict(self) -> dict[str, object]:
        return asdict(self)


def detailed_connectivity_probe(interface_ip: str | None, primary_url: str,
                                primary_success_text: str, secondary_url: str) -> ProbeResult:
    """Probe effective routing or a source-bound address, retaining safe errors.

    Source binding is deliberately not described as bypassing a TUN interface.
    Response bodies and resolved addresses are never retained in diagnostics.
    """
    base = _curl_base(interface_ip or "")
    if not interface_ip:
        base = base[:3] + base[5:]
    attempts = []
    targets = [(primary_url, "microsoft-connect-test", primary_success_text)]
    if secondary_url:
        targets.append((secondary_url, "android-generate-204", None))
    for url, source, expected in targets:
        try:
            completed = subprocess.run(
                [*base, "-w", "\n%{http_code}", url], capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=14, creationflags=CREATE_NO_WINDOW,
            )
            body, _, code = completed.stdout.rpartition("\n")
            status = int(code) if code.strip().isdigit() else 0
            error = completed.returncode
            valid = not error and (body.strip() == expected and status == 200 if expected is not None else status == 204)
            reason = "ok" if valid else {5: "dns-error", 6: "dns-error", 7: "connect-error", 28: "timeout", 45: "source-bind-error"}.get(error, "curl-error" if error else "redirect" if 300 <= status < 400 else "unexpected-response")
        except subprocess.TimeoutExpired:
            valid, status, error, reason = False, 0, 28, "timeout"
        except OSError:
            valid, status, error, reason = False, 0, -1, "probe-unavailable"
        attempts.append({"target": source, "success": valid, "reason": reason, "http_status": status, "curl_exit_code": error})
        if valid:
            return ProbeResult(True, source, "ok", tuple(attempts))
    reasons = {item["reason"] for item in attempts}
    reason = next(iter(reasons)) if len(reasons) == 1 else "multiple-probe-errors"
    return ProbeResult(False, "all-connectivity-probes-failed", reason, tuple(attempts))
