"""Gmail provider implementation.

Phase 1-2: profile + connection test.
Phase 3: message listing and full MIME message retrieval mapped onto the
provider-neutral NormalizedMessage schema.
"""

import base64
import logging
import re

import httpx
from datetime import datetime, timezone
from email.header import decode_header, make_header

from app.schemas.email import NormalizedMessage
from app.services.email_providers.base import (
    EmailProviderError,
    ProviderCapability,
    ProviderErrorClass,
)

logger = logging.getLogger("cyberguard.connectors.gmail")

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
# Sender rules (Gmail filters) need the settings scope; without re-consent
# Google answers 403 which maps to insufficient_scope.
GMAIL_SETTINGS_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"

_TIMEOUT = httpx.Timeout(15.0)

# Attachments kept as metadata only in Phase 3 (no binary download yet).
_MEDIA_MIME_PREFIXES = ("image/", "audio/", "video/")


class GmailProvider:
    provider = "gmail"
    capabilities = ProviderCapability(
        read_messages=True,
        read_attachments=True,
        modify_labels=True,
        quarantine=True,
        trash=True,
        permanent_delete=True,
        sender_rules=False,
        send_mail=True,
    )

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        self._client = http_client or httpx.AsyncClient(timeout=_TIMEOUT)

    def _error(self, status_code: int, payload: dict | None) -> EmailProviderError:
        """Map Google errors to safe, user-facing error classes."""
        body = payload or {}
        detail = str(body.get("error_description") or body.get("error") or body.get("message") or "")
        code = str(body.get("error") or body.get("status") or "")

        if status_code == 401 or "invalid_grant" in code or "expired" in detail.lower():
            return EmailProviderError(
                ProviderErrorClass.REAUTH_REQUIRED,
                "Gmail authorization expired — reconnect this mailbox.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        if status_code == 403 or "insufficientPermissions" in code or "insufficient" in detail.lower():
            return EmailProviderError(
                ProviderErrorClass.INSUFFICIENT_SCOPE,
                "Gmail access was denied — the granted scopes are insufficient.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        if status_code == 429 or "rateLimitExceeded" in code:
            return EmailProviderError(
                ProviderErrorClass.RATE_LIMITED,
                "Gmail rate limit reached — try again shortly.",
                provider_code=code or None,
                provider_detail=detail or None,
            )
        return EmailProviderError(
            ProviderErrorClass.FAILED,
            f"Gmail request failed (HTTP {status_code}).",
            provider_code=code or None,
            provider_detail=detail or None,
        )

    async def _request(self, method: str, url: str, access_token: str, **kwargs) -> dict:
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            response = await self._client.request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise EmailProviderError(
                ProviderErrorClass.FAILED, f"Gmail request failed: {type(exc).__name__}"
            ) from exc
        if response.status_code >= 400:
            try:
                payload = response.json()
            except Exception:  # noqa: BLE001
                payload = {}
            raise self._error(response.status_code, payload)
        if not response.content:
            return {}
        return response.json()

    async def get_profile(self, access_token: str) -> dict:
        """GET /users/me/profile → {email_address, messages_total, ...}."""
        return await self._request("GET", f"{GMAIL_API_BASE}/users/me/profile", access_token)

    async def test_connection(self, access_token: str) -> dict:
        """Validate the token against the profile endpoint; return safe summary."""
        profile = await self.get_profile(access_token)
        return {
            "provider": self.provider,
            "email_address": profile.get("email_address"),
            "messages_total": profile.get("messages_total"),
            "threads_total": profile.get("threads_total"),
            "ok": True,
        }

    # ------------------------------------------------------------------
    # Phase 3 — mailbox reading
    # ------------------------------------------------------------------

    async def list_messages(self, access_token: str, max_results: int = 50) -> list[dict]:
        """GET /users/me/messages → list of {id, thread_id} (most recent first)."""
        data = await self._request(
            "GET",
            f"{GMAIL_API_BASE}/users/me/messages",
            access_token,
            params={"maxResults": max(1, min(int(max_results), 100))},
        )
        return [
            {"id": item.get("id", ""), "thread_id": item.get("threadId", "")}
            for item in data.get("messages", [])
            if item.get("id")
        ]

    async def get_message(self, access_token: str, message_id: str) -> NormalizedMessage:
        """Fetch a full message and map it to the NormalizedMessage schema."""
        raw = await self._request(
            "GET",
            f"{GMAIL_API_BASE}/users/me/messages/{message_id}",
            access_token,
            params={"format": "full"},
        )
        return self._normalize(message_id, raw)

    # --- normalization helpers ---

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Gmail base64url body decode (padding-safe)."""
        padded = data.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        return base64.b64decode(padded)

    @staticmethod
    def _decode_mime_header(value: str) -> str:
        try:
            return str(make_header(decode_header(value or "")))
        except Exception:  # noqa: BLE001 - undecodable headers stay raw
            return value or ""

    def _collect_parts(self, payload: dict, parts_out: list[dict]) -> None:
        parts_out.append(payload)
        for part in payload.get("parts", []) or []:
            self._collect_parts(part, parts_out)

    def _extract_bodies_and_attachments(self, payload: dict) -> tuple[str | None, str | None, list[dict]]:
        parts: list[dict] = []
        self._collect_parts(payload, parts)

        body_text: str | None = None
        body_html: str | None = None
        attachments: list[dict] = []

        for part in parts:
            mime = part.get("mimeType", "")
            body = part.get("body", {}) or {}
            data = body.get("data")
            filename = part.get("filename") or ""
            if filename or part.get("body", {}).get("attachmentId"):
                # Anything with a filename/attachmentId is an attachment; still
                # inline text/* parts without filenames remain body candidates.
                if filename and mime:
                    attachments.append(
                        {
                            "filename": filename,
                            "mime_type": mime,
                            "size": int(body.get("size") or 0),
                            "attachment_id": body.get("attachmentId"),
                            "is_media": mime.startswith(_MEDIA_MIME_PREFIXES),
                        }
                    )
                    continue
            if data and mime == "text/plain" and body_text is None:
                body_text = self._b64url_decode(data).decode("utf-8", errors="replace")
            elif data and mime == "text/html" and body_html is None:
                body_html = self._b64url_decode(data).decode("utf-8", errors="replace")

        if body_text is None and body_html is None and payload.get("body", {}).get("data"):
            # Single-part messages put the body directly on the payload.
            body_text = self._b64url_decode(payload["body"]["data"]).decode("utf-8", errors="replace")

        return body_text, body_html, attachments

    def _normalize(self, message_id: str, raw: dict) -> NormalizedMessage:
        headers_map = {
            self._decode_mime_header(h.get("name", "")): self._decode_mime_header(h.get("value", ""))
            for h in raw.get("payload", {}).get("headers", [])
        }
        body_text, body_html, attachments = self._extract_bodies_and_attachments(raw.get("payload", {}) or {})

        internal_date = raw.get("internalDate")
        received_at = None
        if internal_date:
            try:
                received_at = datetime.fromtimestamp(int(internal_date) / 1000, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                received_at = None

        label_ids = raw.get("labelIds", []) or []
        is_read = "UNREAD" not in label_ids

        # Strip HTML tags for a text fallback when only HTML is present.
        if body_text is None and body_html is not None:
            body_text = re.sub(r"<[^>]+>", " ", body_html)
            body_text = re.sub(r"\s+", " ", body_text).strip()

        return NormalizedMessage(
            provider_message_id=message_id,
            provider="gmail",
            sender=headers_map.get("From", ""),
            recipients=[
                r.strip()
                for r in re.split("[,;]", headers_map.get("To", ""))
                if r.strip()
            ],
            subject=headers_map.get("Subject", ""),
            body_text=body_text,
            body_html=body_html,
            headers=headers_map,
            attachments_meta=attachments,
            received_at=received_at,
            is_read=is_read,
        )

    # ------------------------------------------------------------------
    # Phase 4 — provider-backed enforcement
    # ------------------------------------------------------------------

    QUARANTINE_LABEL_NAME = "CYBERGUARD-Quarantine"

    async def ensure_quarantine_label(self, access_token: str) -> str:
        """Find or create the CYBERGUARD-Quarantine label; return its id."""
        labels = await self._request("GET", f"{GMAIL_API_BASE}/users/me/labels", access_token)
        for label in labels.get("labels", []):
            if label.get("name") == self.QUARANTINE_LABEL_NAME:
                return str(label["id"])
        created = await self._request(
            "POST",
            f"{GMAIL_API_BASE}/users/me/labels",
            access_token,
            json={
                "name": self.QUARANTINE_LABEL_NAME,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        )
        return str(created["id"])

    async def quarantine_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict:
        """Archive the message out of INBOX into the quarantine label."""
        return await self._request(
            "POST",
            f"{GMAIL_API_BASE}/users/me/messages/{message_id}/modify",
            access_token,
            json={"addLabelIds": [quarantine_label], "removeLabelIds": ["INBOX"]},
        )

    async def release_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict:
        """Return a quarantined message to the inbox."""
        return await self._request(
            "POST",
            f"{GMAIL_API_BASE}/users/me/messages/{message_id}/modify",
            access_token,
            json={"addLabelIds": ["INBOX"], "removeLabelIds": [quarantine_label]},
        )

    async def delete_message(self, access_token: str, message_id: str, permanent: bool) -> dict:
        """Trash the message, or permanently delete when permitted+enabled."""
        if permanent:
            await self._request("DELETE", f"{GMAIL_API_BASE}/users/me/messages/{message_id}", access_token)
            return {"deleted": True, "permanent": True}
        return await self._request(
            "POST", f"{GMAIL_API_BASE}/users/me/messages/{message_id}/trash", access_token
        )

    async def create_sender_rule(self, access_token: str, sender_email: str, target_label: str) -> dict:
        """Create a Gmail filter auto-quarantining future mail from the sender.

        Requires https://www.googleapis.com/auth/gmail.settings.basic; without
        the granted scope Google answers 403 which maps to insufficient_scope.
        """
        return await self._request(
            "POST",
            f"{GMAIL_API_BASE}/users/me/settings/filters",
            access_token,
            json={
                "criteria": {"from": sender_email},
                "action": {"addLabelIds": [target_label], "removeLabelIds": ["INBOX"]},
            },
        )

    async def delete_sender_rule(self, access_token: str, rule_id: str) -> dict:
        await self._request(
            "DELETE", f"{GMAIL_API_BASE}/users/me/settings/filters/{rule_id}", access_token
        )
        return {"deleted": True, "rule_id": rule_id}

    async def close(self) -> None:
        await self._client.aclose()


gmail_provider = GmailProvider()
