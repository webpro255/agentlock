"""Tests for agentlock.session — Session and SessionStore."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from agentlock.exceptions import SessionExpiredError
from agentlock.session import Session, SessionStore
from agentlock.types import DataBoundary

# ---- Session --------------------------------------------------------------

class TestSession:
    def test_creation_defaults(self):
        s = Session(user_id="alice", role="admin")
        assert s.user_id == "alice"
        assert s.role == "admin"
        assert s.data_boundary == DataBoundary.AUTHENTICATED_USER_ONLY
        assert s.session_id.startswith("als_")
        assert s.metadata == {}

    def test_expires_at_set_from_max_duration(self):
        before = time.time()
        s = Session(user_id="u", role="r", _max_duration=300)
        after = time.time()
        assert s.expires_at >= before + 300
        assert s.expires_at <= after + 300

    def test_is_expired_false_when_fresh(self):
        s = Session(user_id="u", role="r")
        assert s.is_expired is False

    def test_is_expired_true_after_expiry(self):
        now = time.time()
        s = Session(user_id="u", role="r", _max_duration=10)
        with patch("agentlock.session.time") as mock_time:
            mock_time.time.return_value = now + 20
            assert s.is_expired is True

    def test_validate_raises_when_expired(self):
        now = time.time()
        s = Session(user_id="u", role="r", _max_duration=1)
        with patch("agentlock.session.time") as mock_time:
            mock_time.time.return_value = now + 100
            with pytest.raises(SessionExpiredError):
                s.validate()

    def test_validate_ok_when_valid(self):
        s = Session(user_id="u", role="r")
        s.validate()  # should not raise

    def test_remaining_seconds_positive(self):
        s = Session(user_id="u", role="r", _max_duration=1000)
        assert s.remaining_seconds > 0

    def test_remaining_seconds_zero_when_expired(self):
        now = time.time()
        s = Session(user_id="u", role="r", _max_duration=1)
        with patch("agentlock.session.time") as mock_time:
            mock_time.time.return_value = now + 100
            assert s.remaining_seconds == 0.0

    def test_unique_session_ids(self):
        s1 = Session(user_id="u", role="r")
        s2 = Session(user_id="u", role="r")
        assert s1.session_id != s2.session_id

    def test_custom_data_boundary(self):
        s = Session(user_id="u", role="r", data_boundary=DataBoundary.ORGANIZATION)
        assert s.data_boundary == DataBoundary.ORGANIZATION


# ---- SessionStore ---------------------------------------------------------

class TestSessionStore:
    def test_create_returns_session(self):
        store = SessionStore()
        s = store.create("alice", "admin")
        assert s.user_id == "alice"
        assert s.role == "admin"
        assert len(store) == 1

    def test_get_returns_session(self):
        store = SessionStore()
        s = store.create("alice", "admin")
        fetched = store.get(s.session_id)
        assert fetched is not None
        assert fetched.session_id == s.session_id

    def test_get_returns_none_for_unknown(self):
        store = SessionStore()
        assert store.get("nonexistent") is None

    def test_get_by_user_returns_correct_session(self):
        store = SessionStore()
        store.create("alice", "admin")
        store.create("bob", "user")
        s = store.get_by_user("alice")
        assert s is not None
        assert s.user_id == "alice"

    def test_get_by_user_returns_none_for_unknown(self):
        store = SessionStore()
        assert store.get_by_user("nobody") is None

    def test_destroy_removes_session(self):
        store = SessionStore()
        s = store.create("alice", "admin")
        store.destroy(s.session_id)
        assert store.get(s.session_id) is None
        assert store.get_by_user("alice") is None
        assert len(store) == 0

    def test_destroy_nonexistent_is_noop(self):
        store = SessionStore()
        store.destroy("fake")  # should not raise

    def test_get_expired_returns_none_and_cleans_up(self):
        store = SessionStore()
        now = time.time()
        s = store.create("alice", "admin", max_duration=1)
        with patch("agentlock.session.time") as mock_time:
            mock_time.time.return_value = now + 100
            assert store.get(s.session_id) is None
        assert len(store) == 0

    def test_cleanup_expired_removes_old_sessions(self):
        store = SessionStore()
        now = time.time()
        store.create("alice", "admin", max_duration=1)
        store.create("bob", "user", max_duration=99999)

        with patch("agentlock.session.time") as mock_time:
            mock_time.time.return_value = now + 10
            removed = store.cleanup_expired()

        assert removed == 1
        assert len(store) == 1

    def test_cleanup_expired_no_expired(self):
        store = SessionStore()
        store.create("alice", "admin", max_duration=99999)
        removed = store.cleanup_expired()
        assert removed == 0

    def test_len(self):
        store = SessionStore()
        assert len(store) == 0
        store.create("a", "r")
        store.create("b", "r")
        assert len(store) == 2

    def test_create_with_metadata(self):
        store = SessionStore()
        s = store.create("alice", "admin", metadata={"ip": "1.2.3.4"})
        assert s.metadata == {"ip": "1.2.3.4"}

    def test_create_replaces_previous_for_same_user(self):
        store = SessionStore()
        store.create("alice", "admin")
        s2 = store.create("alice", "user")
        # The user_sessions mapping now points to s2
        fetched = store.get_by_user("alice")
        assert fetched is not None
        assert fetched.session_id == s2.session_id
