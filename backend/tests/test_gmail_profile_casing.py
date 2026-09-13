"""Regression: Gmail profile response uses the REAL API casing.

The live Gmail API returns camelCase (`emailAddress`); the callback used to
read `email_address` and failed every real connection with
" Gmail profile returned no email address" while the mocked tests passed
(their fakes happened to use snake_case). This test pins the normalization to
the real wire format via an httpx MockTransport.
"""

import pytest
from httpx import AsyncClient, MockTransport, Response

from app.services.email_providers.gmail import GmailProvider

pytestmark = [pytest.mark.http]


def _gmail_like_transport() -> MockTransport:
    """Transport returning payloads EXACTLY as the real Gmail API shapes them
    (camelCase keys — do not 'fix' these to snake_case)."""

    def handler(request):
        url = str(request.url)
        if url.endswith("/users/me/profile"):
            return Response(200, json={
                "emailAddress": "user@gmail.com",
                "messagesTotal": 4211,
                "threadsTotal": 3120,
                "historyId": "5f47",
            })
        return Response(404, json={"error": "not found"})

    return MockTransport(handler)


@pytest.mark.http
async def test_get_profile_normalizes_real_gmail_casing():
    provider = GmailProvider(http_client=AsyncClient(transport=_gmail_like_transport()))
    profile = await provider.get_profile("mock-access-token")

    assert profile["email_address"] == "user@gmail.com", (
        "get_profile must map the live Gmail key 'emailAddress' to 'email_address'"
    )
    assert profile["messages_total"] == 4211
    await provider.close()


@pytest.mark.http
async def test_test_connection_uses_normalized_profile():
    provider = GmailProvider(http_client=AsyncClient(transport=_gmail_like_transport()))
    result = await provider.test_connection("mock-access-token")

    assert result["ok"] is True
    assert result["email_address"] == "user@gmail.com"
    assert result["messages_total"] == 4211
    await provider.close()
