from __future__ import annotations

import json
import secrets
import sys
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class _WorkspaceFolder:
    def __enter__(self) -> Path:
        self.path = ROOT / ".test-output" / f"dorm-inline-survey-{secrets.token_hex(6)}"
        self.path.mkdir(parents=True)
        return self.path

    def __exit__(self, exc_type, exc, traceback) -> None:
        expected_parent = (ROOT / ".test-output").resolve()
        if self.path.resolve().parent != expected_parent:
            raise AssertionError("test cleanup target escaped .test-output")
        for path in sorted(self.path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        self.path.rmdir()


def _write_capture(path: Path, *, complete: bool = True, secret: str = "") -> None:
    records = [
        {
            "event": "capture-started",
            "capture_id": "safe-capture",
            "privacy_profile": "metadata-only-v2",
            "portal_host": "202.195.176.60",
        },
        {
            "event": "inline-wrapper-analysis",
            "capture_id": "safe-capture",
            "script_id": "0123456789abcdef",
            "function": "_$dP",
            "line": 0,
            "column": 32190,
            "target": {
                "scheme": "http",
                "host": "202.195.176.60",
                "path": "/eportal/network/serviceLogin",
                "query_fields": ["ttbYz9WP"],
            },
            "source_meta": {
                "bytes": 40000,
                "sha256": "a" * 64,
                "window_start": 28000,
                "window_end": 40000,
            },
            "features": {"date_now": 1, "math_random": 1},
            "token_window": {
                "format": "redacted-js-token-window-v1",
                "tokens": ["function", "_$dP", "(", "id1", ")", "str:ttbYz9WP"],
            },
            "unexpected_secret": secret,
        },
        {
            "event": "capture-stopped",
            "capture_id": "safe-capture",
            "complete": complete,
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n",
        encoding="utf-8",
    )


class DormInlineSurveyTests(unittest.TestCase):
    def test_completed_capture_exports_only_allowlisted_redacted_analysis(self):
        from campus_net_assistant.dorm_inline_survey import build_inline_wrapper_survey

        with _WorkspaceFolder() as folder:
            capture = folder / "capture-test.jsonl"
            secret = "must-not-leave-source-capture"
            _write_capture(capture, secret=secret)
            result = build_inline_wrapper_survey(capture, output_root=folder / "output")
            self.assertIsNotNone(result)
            self.assertEqual(result.analysis_count, 1)
            with zipfile.ZipFile(result.archive_path) as archive:
                self.assertEqual(sorted(archive.namelist()), ["analysis.json", "manifest.json"])
                payload = "\n".join(
                    archive.read(name).decode("utf-8") for name in archive.namelist()
                )
            self.assertNotIn(secret, payload)
            self.assertNotIn("capture-test.jsonl", archive.namelist())
            self.assertIn("ttbYz9WP", payload)
            self.assertIn("redacted-js-token-window-v1", payload)

    def test_incomplete_capture_does_not_export(self):
        from campus_net_assistant.dorm_inline_survey import build_inline_wrapper_survey

        with _WorkspaceFolder() as folder:
            capture = folder / "capture-test.jsonl"
            _write_capture(capture, complete=False)
            result = build_inline_wrapper_survey(capture, output_root=folder / "output")
            self.assertIsNone(result)
            self.assertFalse((folder / "output").exists())


if __name__ == "__main__":
    unittest.main()
