import pytest
from aioresponses import aioresponses
from pytest_mock import MockerFixture

from mcp_tracker.tracker.custom.client import (
    WorkloadIdentitySettings,
    WorkloadIdentityStore,
)


class TestWorkloadIdentityStore:
    async def test_fetch_iam_token_success(
        self, tmp_path, mocker: MockerFixture
    ):
        """Test successful token exchange via WLIF endpoint."""
        # Create a fake projected token file
        token_file = tmp_path / "token"
        token_file.write_text("fake-projected-jwt-token")

        settings = WorkloadIdentitySettings(
            token_path=str(token_file),
            token_exchange_url="https://auth.yandex.cloud/oauth/token",
        )

        store = WorkloadIdentityStore(settings)

        try:
            await store.prepare()

            with aioresponses() as m:
                m.post(
                    "https://auth.yandex.cloud/oauth/token",
                    payload={
                        "access_token": "fake-iam-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    },
                )

                token = await store.get_iam_token()
                assert token == "fake-iam-token"
        finally:
            await store.close()

    async def test_fetch_iam_token_missing_file(self, tmp_path):
        """Test error when projected token file does not exist."""
        settings = WorkloadIdentitySettings(
            token_path=str(tmp_path / "nonexistent"),
        )

        store = WorkloadIdentityStore(settings)

        try:
            await store.prepare()

            with pytest.raises(
                RuntimeError, match="Workload Identity token file not found"
            ):
                await store.get_iam_token()
        finally:
            await store.close()

    async def test_fetch_iam_token_http_error(self, tmp_path):
        """Test error when token exchange endpoint returns non-200."""
        token_file = tmp_path / "token"
        token_file.write_text("fake-projected-jwt-token")

        settings = WorkloadIdentitySettings(
            token_path=str(token_file),
            token_exchange_url="https://auth.yandex.cloud/oauth/token",
        )

        store = WorkloadIdentityStore(settings)

        try:
            await store.prepare()

            with aioresponses() as m:
                m.post(
                    "https://auth.yandex.cloud/oauth/token",
                    status=401,
                    body="invalid token",
                )

                with pytest.raises(
                    RuntimeError, match="Failed to exchange projected token"
                ):
                    await store.get_iam_token()
        finally:
            await store.close()

    async def test_fetch_iam_token_missing_access_token(self, tmp_path):
        """Test error when response doesn't contain access_token."""
        token_file = tmp_path / "token"
        token_file.write_text("fake-projected-jwt-token")

        settings = WorkloadIdentitySettings(
            token_path=str(token_file),
            token_exchange_url="https://auth.yandex.cloud/oauth/token",
        )

        store = WorkloadIdentityStore(settings)

        try:
            await store.prepare()

            with aioresponses() as m:
                m.post(
                    "https://auth.yandex.cloud/oauth/token",
                    payload={"error": "unauthorized"},
                )

                with pytest.raises(
                    RuntimeError, match="Token exchange response missing"
                ):
                    await store.get_iam_token()
        finally:
            await store.close()

    async def test_token_is_cached(self, tmp_path):
        """Test that subsequent calls return cached token without refetching."""
        token_file = tmp_path / "token"
        token_file.write_text("fake-projected-jwt-token")

        settings = WorkloadIdentitySettings(
            token_path=str(token_file),
            token_exchange_url="https://auth.yandex.cloud/oauth/token",
        )

        store = WorkloadIdentityStore(settings)

        try:
            await store.prepare()

            with aioresponses() as m:
                m.post(
                    "https://auth.yandex.cloud/oauth/token",
                    payload={"access_token": "cached-iam-token"},
                )

                token1 = await store.get_iam_token()
                token2 = await store.get_iam_token()

                assert token1 == "cached-iam-token"
                assert token2 == "cached-iam-token"
                # Should only have called the endpoint once
                assert len(m.requests) == 1
        finally:
            await store.close()


class TestWorkloadIdentitySettings:
    def test_default_token_path(self):
        """Test default token path matches Yandex Cloud convention."""
        settings = WorkloadIdentitySettings()
        assert (
            settings.token_path
            == "/var/run/secrets/yandex.cloud/serviceaccount/token"
        )

    def test_default_exchange_url(self):
        """Test default token exchange URL."""
        settings = WorkloadIdentitySettings()
        assert settings.token_exchange_url == "https://auth.yandex.cloud/oauth/token"

    def test_custom_settings(self):
        """Test custom settings override defaults."""
        settings = WorkloadIdentitySettings(
            token_path="/custom/path/token",
            token_exchange_url="https://custom.example.com/oauth",
        )
        assert settings.token_path == "/custom/path/token"
        assert settings.token_exchange_url == "https://custom.example.com/oauth"
