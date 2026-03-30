"""Tests for the AgentLock CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentlock.cli import main


class TestVersion:
    def test_version_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit, match="0"):
            main(["--version"])
        captured = capsys.readouterr()
        assert "agentlock" in captured.out
        assert "1.2.0" in captured.out


class TestInit:
    def test_creates_file(self, tmp_path: Path) -> None:
        output = tmp_path / "tool.json"
        result = main(["init", "-o", str(output)])
        assert result == 0
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["name"] == "my_tool"
        assert "agentlock" in data
        assert data["agentlock"]["version"] == "1.1"

    def test_default_output_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = main(["init"])
        assert result == 0
        assert (tmp_path / "agentlock-tool.json").exists()


class TestValidate:
    def test_valid_tool(self, tmp_path: Path) -> None:
        tool = {
            "name": "test_tool",
            "agentlock": {
                "version": "1.0",
                "risk_level": "medium",
                "requires_auth": True,
                "allowed_roles": ["user"],
            },
        }
        path = tmp_path / "tool.json"
        path.write_text(json.dumps(tool))
        result = main(["validate", str(path)])
        assert result == 0

    def test_valid_permissions_only(self, tmp_path: Path) -> None:
        perms = {
            "version": "1.0",
            "risk_level": "low",
            "requires_auth": False,
            "allowed_roles": ["viewer"],
        }
        path = tmp_path / "perms.json"
        path.write_text(json.dumps(perms))
        result = main(["validate", str(path)])
        assert result == 0

    def test_invalid_risk_level(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        tool = {
            "name": "bad_tool",
            "agentlock": {"risk_level": "mega_danger"},
        }
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(tool))
        result = main(["validate", str(path)])
        assert result == 1
        captured = capsys.readouterr()
        assert "INVALID" in captured.out

    def test_file_not_found(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["validate", "/tmp/nonexistent_agentlock_test.json"])
        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_invalid_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json {{{")
        result = main(["validate", str(path)])
        assert result == 1
        captured = capsys.readouterr()
        assert "invalid JSON" in captured.err


class TestInspect:
    def test_inspect_valid_tool(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        tool = {
            "name": "send_email",
            "agentlock": {
                "risk_level": "high",
                "requires_auth": True,
                "allowed_roles": ["admin"],
                "rate_limit": {"max_calls": 5, "window_seconds": 3600},
            },
        }
        path = tmp_path / "tool.json"
        path.write_text(json.dumps(tool))
        result = main(["inspect", str(path)])
        assert result == 0
        captured = capsys.readouterr()
        assert "send_email" in captured.out
        assert "HIGH" in captured.out
        assert "admin" in captured.out
        assert "5 calls" in captured.out

    def test_inspect_file_not_found(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["inspect", "/tmp/nonexistent_agentlock_test.json"])
        assert result == 1

    def test_inspect_no_roles_shows_deny_all(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        tool = {
            "name": "locked",
            "agentlock": {"risk_level": "critical"},
        }
        path = tmp_path / "tool.json"
        path.write_text(json.dumps(tool))
        result = main(["inspect", str(path)])
        assert result == 0
        captured = capsys.readouterr()
        assert "DENY ALL" in captured.out


class TestSchema:
    def test_outputs_valid_json(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main(["schema"])
        assert result == 0
        captured = capsys.readouterr()
        schema = json.loads(captured.out)
        assert "properties" in schema
        assert "risk_level" in schema["properties"]


class TestAudit:
    def test_audit_empty_log(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.touch()
        result = main(["audit", "--log", str(log_path)])
        assert result == 0
        captured = capsys.readouterr()
        assert "No audit records found" in captured.out

    def test_audit_with_records(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        log_path = tmp_path / "audit.jsonl"
        import time

        record = {
            "audit_id": "agentlock-test-001",
            "timestamp": time.time(),
            "tool_name": "send_email",
            "user_id": "alice",
            "role": "admin",
            "action": "allowed",
            "reason": "",
            "risk_level": "high",
        }
        log_path.write_text(json.dumps(record) + "\n")
        result = main(["audit", "--log", str(log_path)])
        assert result == 0
        captured = capsys.readouterr()
        assert "send_email" in captured.out
        assert "1 record(s)" in captured.out

    def test_audit_filter_by_tool(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        log_path = tmp_path / "audit.jsonl"
        import time

        now = time.time()
        records = [
            {"audit_id": "t1", "timestamp": now, "tool_name": "read_db",
             "action": "allowed"},
            {"audit_id": "t2", "timestamp": now, "tool_name": "send_email",
             "action": "denied"},
        ]
        log_path.write_text(
            "\n".join(json.dumps(r) for r in records) + "\n"
        )
        result = main(["audit", "--log", str(log_path), "--tool", "send_email"])
        assert result == 0
        captured = capsys.readouterr()
        assert "send_email" in captured.out
        assert "read_db" not in captured.out
        assert "1 record(s)" in captured.out


class TestNoCommand:
    def test_no_args_prints_help(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = main([])
        assert result == 0
        captured = capsys.readouterr()
        assert "agentlock" in captured.out.lower()
