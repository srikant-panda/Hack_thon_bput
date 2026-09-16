"""Google Cloud Pub/Sub push notification validator for Gmail watch subscriptions."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from fastapi import HTTPException, Request

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.pubsub_validator")


async def validate_pubsub_message(request: Request) -> dict[str, Any]:
    """Validate and parse Google Cloud Pub/Sub push notification message.

    Steps:
    1. Extract Authorization header (Bearer token) or query param (token).
    2. If GOOGLE_PUBSUB_VERIFICATION_TOKEN is set: verify match; else skip (dev mode).
    3. Decode request body -> parse JSON.
    4. Validate structure: {message: {data: base64, messageId: str}, subscription: str}.
    5. Decode base64 data -> {emailAddress: str, historyId: str}.
    6. If GMAIL_PUBSUB_AUDIENCE is set: verify JWT aud claim.
    7. Return {email_address, history_id, message_id, subscription}.
    8. On any failure: raise HTTPException(400, "Invalid Pub/Sub message").
    """
    settings = get_settings()

    # 1. Extract Authorization header or query param
    auth_header = request.headers.get("Authorization", "").strip()
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "token" in request.query_params:
        token = request.query_params.get("token", "").strip()

    # 2. Verify verification token if configured
    verification_token = settings.GOOGLE_PUBSUB_VERIFICATION_TOKEN.strip()
    if verification_token:
        if not token or token != verification_token:
            logger.warning("Pub/Sub verification token mismatch or missing")
            raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    # 3. Read body and parse JSON
    try:
        body_bytes = await request.body()
        if not body_bytes:
            raise ValueError("Empty body")
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("Pub/Sub body JSON parse failure: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message") from exc

    # 4. Validate structure
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    subscription = payload.get("subscription")
    message = payload.get("message")
    if not isinstance(subscription, str) or not isinstance(message, dict):
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    raw_data = message.get("data")
    message_id = message.get("messageId")
    if not isinstance(raw_data, str) or not isinstance(message_id, str):
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    # 5. Decode base64 data -> extract emailAddress and historyId
    try:
        data_bytes = base64.b64decode(raw_data, validate=True)
        data_json = json.loads(data_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("Failed to base64 decode or parse Pub/Sub data payload: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message") from exc

    if not isinstance(data_json, dict):
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    email_address = data_json.get("emailAddress") or data_json.get("email_address")
    history_id = data_json.get("historyId") or data_json.get("history_id")

    if not email_address or not history_id:
        logger.warning("Pub/Sub message data missing emailAddress or historyId")
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")

    # 6. Verify audience if set (for Google OIDC JWT signed pushes)
    audience = settings.GMAIL_PUBSUB_AUDIENCE
    if audience and token:
        parts = token.split(".")
        if len(parts) == 3:
            try:
                payload_b64 = parts[1]
                rem = len(payload_b64) % 4
                if rem > 0:
                    payload_b64 += "=" * (4 - rem)
                claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                token_aud = claims.get("aud")
                if token_aud != audience:
                    logger.warning("JWT audience mismatch: expected %s, got %s", audience, token_aud)
                    raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")
            except HTTPException:
                raise
            except Exception as exc:
                logger.warning("Error inspecting token audience: %s", exc)
                raise HTTPException(status_code=400, detail="Invalid Pub/Sub message") from exc

    # 7. Return extracted payload
    return {
        "email_address": str(email_address).strip(),
        "history_id": str(history_id).strip(),
        "message_id": str(message_id).strip(),
        "subscription": str(subscription).strip(),
    }
