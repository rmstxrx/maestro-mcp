"""Tests for maestro_oauth.py."""
import asyncio
import hashlib
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from maestro_oauth import (
    AUTH_CODE_TTL,
    CLAUDE_AI_CALLBACK,
    MaestroOAuthProvider,
    _audit,
)


@pytest.fixture
def provider():
    return MaestroOAuthProvider(
        issuer_url="https://test.example.com",
        host_names=["host-a", "host-b"],
    )


def _make_client_info(client_id="test-client", client_name="Test App",
                       redirect_uris=None):
    """Create a mock OAuthClientInformationFull."""
    mock = MagicMock()
    mock.client_id = client_id
    mock.client_name = client_name
    mock.client_uri = None
    mock.redirect_uris = redirect_uris or ["https://example.com/callback"]
    return mock


def _make_params(redirect_uri="https://example.com/callback", state="test-state"):
    """Create a mock AuthorizationParams."""
    mock = MagicMock()
    mock.redirect_uri = redirect_uri
    mock.state = state
    mock.scopes = ["maestro"]
    mock.code_challenge = "test-challenge"
    mock.redirect_uri_provided_explicitly = True
    mock.resource = None
    return mock


# ---------------------------------------------------------------------------
# Registration rate limiting
# ---------------------------------------------------------------------------

class TestRegistrationRateLimit:
    @pytest.mark.asyncio
    async def test_allows_under_limit(self, provider):
        for i in range(10):
            client = _make_client_info(client_id=f"client-{i}")
            await provider.register_client(client)
        assert len(provider.clients) == 10

    @pytest.mark.asyncio
    async def test_rejects_over_limit(self, provider):
        for i in range(10):
            client = _make_client_info(client_id=f"client-{i}")
            await provider.register_client(client)

        with pytest.raises(ValueError, match="Too many registration"):
            client = _make_client_info(client_id="client-11")
            await provider.register_client(client)

    @pytest.mark.asyncio
    async def test_lock_prevents_race(self, provider):
        """Concurrent registrations should still respect the rate limit."""
        clients = [_make_client_info(client_id=f"client-{i}") for i in range(15)]
        results = await asyncio.gather(
            *[provider.register_client(c) for c in clients],
            return_exceptions=True,
        )
        successes = [r for r in results if not isinstance(r, Exception)]
        failures = [r for r in results if isinstance(r, Exception)]
        assert len(successes) == 10
        assert len(failures) == 5


# ---------------------------------------------------------------------------
# Client metadata validation
# ---------------------------------------------------------------------------

class TestClientMetadataValidation:
    @pytest.mark.asyncio
    async def test_rejects_long_client_name(self, provider):
        client = _make_client_info(client_name="x" * 257)
        with pytest.raises(ValueError, match="client_name"):
            await provider.register_client(client)

    @pytest.mark.asyncio
    async def test_allows_normal_client_name(self, provider):
        client = _make_client_info(client_name="x" * 256)
        await provider.register_client(client)
        assert client.client_id in provider.clients

    @pytest.mark.asyncio
    async def test_rejects_long_client_uri(self, provider):
        client = _make_client_info()
        client.client_uri = "https://example.com/" + "x" * 2048
        with pytest.raises(ValueError, match="client_uri"):
            await provider.register_client(client)


# ---------------------------------------------------------------------------
# Claude.ai auto-approval
# ---------------------------------------------------------------------------

class TestClaudeAiAutoApproval:
    @pytest.mark.asyncio
    async def test_claude_ai_redirect_auto_approves(self, provider):
        client = _make_client_info()
        await provider.register_client(client)
        params = _make_params(redirect_uri=CLAUDE_AI_CALLBACK)

        result = await provider.authorize(client, params)

        # Should return a redirect URL with code, not an /approve page
        assert "/approve" not in result
        assert "code=" in result
        # Should NOT create a pending approval
        assert len(provider.pending_approvals) == 0

    @pytest.mark.asyncio
    async def test_non_claude_redirect_goes_to_consent(self, provider):
        client = _make_client_info()
        await provider.register_client(client)
        params = _make_params(redirect_uri="https://other.example.com/callback")

        result = await provider.authorize(client, params)

        # Should redirect to the consent page
        assert "/approve?id=" in result
        assert len(provider.pending_approvals) == 1


# ---------------------------------------------------------------------------
# Pending approvals cleanup
# ---------------------------------------------------------------------------

class TestPendingApprovalsCleanup:
    @pytest.mark.asyncio
    async def test_expired_approvals_cleaned_on_authorize(self, provider):
        client = _make_client_info()
        await provider.register_client(client)

        # Create an expired approval manually
        provider.pending_approvals["old-id"] = {
            "client_id": client.client_id,
            "client_name": "test",
            "params": _make_params(),
            "created_at": time.time() - AUTH_CODE_TTL - 10,
        }
        assert "old-id" in provider.pending_approvals

        # Trigger a new authorization (non-Claude.ai)
        params = _make_params(redirect_uri="https://other.example.com/callback")
        await provider.authorize(client, params)

        # Old approval should be cleaned up
        assert "old-id" not in provider.pending_approvals
        # New approval should exist
        assert len(provider.pending_approvals) == 1


# ---------------------------------------------------------------------------
# PIN rate limiting
# ---------------------------------------------------------------------------

class TestPinRateLimit:
    @pytest.mark.asyncio
    async def test_pin_failures_tracked(self, provider):
        # Simulate failed PIN attempts
        for _ in range(3):
            provider._pin_fail_timestamps.append(time.time())
        assert len(provider._pin_fail_timestamps) == 3

    def test_pin_rate_limit_config(self, provider):
        assert provider._PIN_FAIL_LIMIT == 5
        assert provider._PIN_FAIL_WINDOW == 300


# ---------------------------------------------------------------------------
# Token expiry and revocation audit
# ---------------------------------------------------------------------------

class TestTokenLifecycle:
    @pytest.mark.asyncio
    async def test_expired_token_returns_none(self, provider):
        from maestro_oauth import AccessToken
        # Store an already-expired token
        provider.access_tokens["expired-tok"] = AccessToken(
            token="expired-tok",
            client_id="test",
            scopes=["maestro"],
            expires_at=int(time.time()) - 100,
        )
        result = await provider.load_access_token("expired-tok")
        assert result is None
        assert "expired-tok" not in provider.access_tokens

    @pytest.mark.asyncio
    async def test_valid_token_returned(self, provider):
        from maestro_oauth import AccessToken
        provider.access_tokens["valid-tok"] = AccessToken(
            token="valid-tok",
            client_id="test",
            scopes=["maestro"],
            expires_at=int(time.time()) + 3600,
        )
        result = await provider.load_access_token("valid-tok")
        assert result is not None
        assert result.client_id == "test"
