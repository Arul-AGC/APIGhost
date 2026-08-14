"""Tests for flexible authentication modes."""

import base64
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from apighost.models import AuthMode
from apighost.executor import ExecutorConfig, ChainExecutor, _mask_token


class TestAuthMode:
    """Test AuthMode enum."""

    def test_bearer_mode(self):
        assert AuthMode("bearer") == AuthMode.BEARER

    def test_api_key_mode(self):
        assert AuthMode("api_key") == AuthMode.API_KEY

    def test_cookie_mode(self):
        assert AuthMode("cookie") == AuthMode.COOKIE

    def test_basic_mode(self):
        assert AuthMode("basic") == AuthMode.BASIC

    def test_custom_mode(self):
        assert AuthMode("custom") == AuthMode.CUSTOM

    def test_invalid_mode(self):
        with pytest.raises(ValueError):
            AuthMode("invalid")


class TestAuthHeaders:
    """Test _auth_headers dispatches correctly by AuthMode."""

    def _make_executor(self, auth_mode=AuthMode.BEARER, auth_header="Authorization", auth_scheme="Bearer"):
        config = ExecutorConfig(
            base_url="http://test.local",
            token_a="token_a_value",
            token_b="token_b_value",
            auth_mode=auth_mode,
            auth_header=auth_header,
            auth_scheme=auth_scheme,
        )
        # Mock the spec to avoid DataGenerator initialization issues
        with patch('apighost.executor.DataGenerator'), \
             patch('apighost.executor.DependencyPrefetcher'):
            executor = ChainExecutor(config, {"paths": {}})
        return executor

    def test_bearer_headers(self):
        executor = self._make_executor(auth_mode=AuthMode.BEARER)
        headers = executor._auth_headers("my_token_123")
        assert headers["Authorization"] == "Bearer my_token_123"
        assert headers["Content-Type"] == "application/json"

    def test_api_key_headers(self):
        executor = self._make_executor(
            auth_mode=AuthMode.API_KEY, auth_header="X-API-Key"
        )
        headers = executor._auth_headers("key_abc123")
        assert headers["X-API-Key"] == "key_abc123"
        assert "Authorization" not in headers

    def test_cookie_headers(self):
        executor = self._make_executor(
            auth_mode=AuthMode.COOKIE, auth_header="session"
        )
        headers = executor._auth_headers("sess_value_xyz")
        assert headers["Cookie"] == "session=sess_value_xyz"

    def test_basic_headers(self):
        executor = self._make_executor(auth_mode=AuthMode.BASIC)
        headers = executor._auth_headers("user:password")
        expected = base64.b64encode(b"user:password").decode()
        assert headers["Authorization"] == f"Basic {expected}"

    def test_custom_headers(self):
        executor = self._make_executor(
            auth_mode=AuthMode.CUSTOM, auth_header="X-Auth-Token"
        )
        headers = executor._auth_headers("custom_token_val")
        assert headers["X-Auth-Token"] == "custom_token_val"


class TestMaskToken:
    """Test token masking utility."""

    def test_long_token(self):
        result = _mask_token("abcdefghijklmnop")
        assert result == "abcd****mnop"

    def test_short_token(self):
        result = _mask_token("abcd")
        assert result == "****abcd"

    def test_very_short_token(self):
        result = _mask_token("ab")
        assert result == "****"

    def test_empty_token(self):
        result = _mask_token("")
        assert result == "****"

    def test_exactly_8_chars(self):
        result = _mask_token("12345678")
        assert result == "****5678"

class TestTokenRefresh:
    """Test token refresh callback."""

    def _make_executor_with_refresh(self, cmd="echo new_token"):
        config = ExecutorConfig(
            base_url="http://test.local",
            token_a="old_token_a",
            token_b="old_token_b",
            token_refresh_cmd=cmd,
        )
        with patch('apighost.executor.DataGenerator'), \
             patch('apighost.executor.DependencyPrefetcher'):
            executor = ChainExecutor(config, {"paths": {}})
        return executor

    def test_refresh_token_success(self):
        executor = self._make_executor_with_refresh(cmd='echo refreshed_token')
        # Note: On Windows, echo includes the command in some shells.
        # We test the method directly with a mock.
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="new_fresh_token\n", stderr=""
            )
            result = executor._refresh_token("a")
            assert result == "new_fresh_token"

    def test_refresh_token_failure(self):
        executor = self._make_executor_with_refresh(cmd='false')
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="auth failed"
            )
            result = executor._refresh_token("a")
            assert result is None

    def test_refresh_not_configured(self):
        config = ExecutorConfig(
            base_url="http://test.local",
            token_a="tok_a",
            token_b="tok_b",
            token_refresh_cmd=None,
        )
        with patch('apighost.executor.DataGenerator'), \
             patch('apighost.executor.DependencyPrefetcher'):
            executor = ChainExecutor(config, {"paths": {}})
        result = executor._refresh_token("a")
        assert result is None
