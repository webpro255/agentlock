"""The out-of-band authentication seam.

AgentLock authorizes; it does not authenticate. `AuthProvider` is the protocol
an external identity provider satisfies, and `StaticAuthProvider` is a
development-only implementation of it.
"""

from __future__ import annotations

import agentlock
from agentlock import AuthProvider, StaticAuthProvider


class TestExports:
    def test_reexported_from_package_root(self):
        assert agentlock.AuthProvider is AuthProvider
        assert agentlock.StaticAuthProvider is StaticAuthProvider

    def test_listed_in_dunder_all(self):
        assert "AuthProvider" in agentlock.__all__
        assert "StaticAuthProvider" in agentlock.__all__


class TestProtocolConformance:
    def test_static_provider_satisfies_the_protocol(self):
        provider = StaticAuthProvider({"alice": "admin"})
        assert isinstance(provider, AuthProvider)

    def test_object_without_the_methods_does_not_satisfy_it(self):
        assert not isinstance(object(), AuthProvider)


class TestStaticAuthProvider:
    def test_verify_returns_none_on_unknown_user(self):
        provider = StaticAuthProvider({"alice": "admin"})
        assert provider.verify("mallory") is None

    def test_verify_returns_identity_for_known_user(self):
        provider = StaticAuthProvider({"alice": "admin", "bob": "user"})
        assert provider.verify("alice") == {"user_id": "alice", "role": "admin"}
        assert provider.verify("bob") == {"user_id": "bob", "role": "user"}

    def test_verify_returns_none_on_empty_registry(self):
        assert StaticAuthProvider({}).verify("alice") is None

    def test_initiate_auth_needs_no_flow(self):
        result = StaticAuthProvider({"alice": "admin"}).initiate_auth()
        assert result["type"] == "static"
