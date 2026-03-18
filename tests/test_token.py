"""Tests for agentlock.token — ExecutionToken and TokenStore."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agentlock.exceptions import TokenExpiredError, TokenInvalidError, TokenReplayedError
from agentlock.token import ExecutionToken, TokenStore
from agentlock.types import TokenStatus

# ---- ExecutionToken -------------------------------------------------------

class TestExecutionToken:
    def test_unique_ids(self):
        t1 = ExecutionToken(tool_name="t", user_id="u", role="r")
        t2 = ExecutionToken(tool_name="t", user_id="u", role="r")
        assert t1.token_id != t2.token_id

    def test_token_id_prefix(self):
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        assert t.token_id.startswith("atk_")

    def test_default_ttl_sets_expires_at(self):
        before = time.time()
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        after = time.time()
        assert t.expires_at >= before + 60
        assert t.expires_at <= after + 60

    def test_is_valid_when_fresh(self):
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        assert t.is_valid is True

    def test_expires_after_ttl(self):
        now = time.time()
        with patch("agentlock.token.time") as mock_time:
            mock_time.time.return_value = now
            t = ExecutionToken(tool_name="t", user_id="u", role="r", _ttl_seconds=10)
            # Still valid at now
            assert t.is_valid is True
            # Expired at now + 11
            mock_time.time.return_value = now + 11
            assert t.is_valid is False

    def test_consume_marks_used(self):
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        t.consume()
        assert t.status == TokenStatus.USED

    def test_double_consume_raises_replayed(self):
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        t.consume()
        with pytest.raises(TokenReplayedError):
            t.consume()

    def test_consume_expired_raises(self):
        now = time.time()
        t = ExecutionToken(tool_name="t", user_id="u", role="r", _ttl_seconds=1)
        with patch("agentlock.token.time") as mock_time:
            mock_time.time.return_value = now + 100
            with pytest.raises(TokenExpiredError):
                t.consume()
        assert t.status == TokenStatus.EXPIRED

    def test_revoke_then_consume_raises(self):
        t = ExecutionToken(tool_name="t", user_id="u", role="r")
        t.revoke()
        assert t.status == TokenStatus.REVOKED
        with pytest.raises(TokenInvalidError):
            t.consume()

    def test_hash_parameters_deterministic(self):
        params = {"to": "bob@co.com", "subject": "Hello"}
        h1 = ExecutionToken.hash_parameters(params)
        h2 = ExecutionToken.hash_parameters(params)
        assert h1 == h2

    def test_hash_parameters_order_independent(self):
        h1 = ExecutionToken.hash_parameters({"a": 1, "b": 2})
        h2 = ExecutionToken.hash_parameters({"b": 2, "a": 1})
        assert h1 == h2

    def test_hash_parameters_different_for_different_input(self):
        h1 = ExecutionToken.hash_parameters({"a": 1})
        h2 = ExecutionToken.hash_parameters({"a": 2})
        assert h1 != h2


# ---- TokenStore -----------------------------------------------------------

class TestTokenStore:
    def test_issue_returns_token(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        assert token.tool_name == "tool"
        assert token.user_id == "user"
        assert token.role == "role"
        assert token.status == TokenStatus.ACTIVE

    def test_issue_with_parameters_binds_hash(self):
        store = TokenStore()
        params = {"key": "value"}
        token = store.issue("tool", "user", "role", parameters=params)
        assert token.parameters_hash == ExecutionToken.hash_parameters(params)

    def test_issue_without_parameters_empty_hash(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        assert token.parameters_hash == ""

    def test_validate_and_consume_succeeds(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        consumed = store.validate_and_consume(token.token_id, "tool")
        assert consumed.status == TokenStatus.USED

    def test_validate_and_consume_wrong_tool_raises(self):
        store = TokenStore()
        token = store.issue("tool_a", "user", "role")
        with pytest.raises(TokenInvalidError, match="tool_a"):
            store.validate_and_consume(token.token_id, "tool_b")

    def test_validate_unknown_token_raises(self):
        store = TokenStore()
        with pytest.raises(TokenInvalidError, match="Unknown"):
            store.validate_and_consume("fake_id", "tool")

    def test_validate_replayed_raises(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        store.validate_and_consume(token.token_id, "tool")
        with pytest.raises(TokenReplayedError):
            store.validate_and_consume(token.token_id, "tool")

    def test_validate_with_parameter_hash_match(self):
        store = TokenStore()
        params = {"x": 1}
        token = store.issue("tool", "user", "role", parameters=params)
        consumed = store.validate_and_consume(token.token_id, "tool", parameters=params)
        assert consumed.status == TokenStatus.USED

    def test_validate_with_parameter_hash_mismatch(self):
        store = TokenStore()
        params = {"x": 1}
        token = store.issue("tool", "user", "role", parameters=params)
        with pytest.raises(TokenInvalidError, match="hash mismatch"):
            store.validate_and_consume(token.token_id, "tool", parameters={"x": 999})

    def test_revoke(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        store.revoke(token.token_id)
        with pytest.raises(TokenInvalidError):
            store.validate_and_consume(token.token_id, "tool")

    def test_revoke_nonexistent_is_noop(self):
        store = TokenStore()
        store.revoke("does_not_exist")  # should not raise

    def test_cleanup_expired_removes_old(self):
        store = TokenStore(default_ttl=1)
        now = time.time()
        store.issue("tool", "user", "role")
        assert len(store) == 1

        with patch("agentlock.token.time") as mock_time:
            mock_time.time.return_value = now + 100
            removed = store.cleanup_expired()

        assert removed == 1
        assert len(store) == 0

    def test_cleanup_expired_keeps_active(self):
        store = TokenStore(default_ttl=9999)
        store.issue("tool", "user", "role")
        removed = store.cleanup_expired()
        assert removed == 0
        assert len(store) == 1

    def test_cleanup_removes_used_tokens(self):
        store = TokenStore()
        token = store.issue("tool", "user", "role")
        store.validate_and_consume(token.token_id, "tool")
        removed = store.cleanup_expired()
        assert removed == 1
        assert len(store) == 0

    def test_len(self):
        store = TokenStore()
        assert len(store) == 0
        store.issue("a", "u", "r")
        store.issue("b", "u", "r")
        assert len(store) == 2

    def test_custom_ttl(self):
        store = TokenStore(default_ttl=5)
        now = time.time()
        token = store.issue("tool", "user", "role")
        assert token.expires_at <= now + 6  # 5s + small tolerance
