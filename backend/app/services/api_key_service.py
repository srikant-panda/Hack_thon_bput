"""Organization API keys: generation, hashing, validation, revocation (ORG-1).

Keys authenticate SERVER-TO-SERVER calls to the org-scoped gateway via the
``org_authorization`` header. Design constraints:

- Only the SHA-256 hash is stored. The plaintext is returned exactly once by
  the create endpoint and never persisted or logged. (SHA-256 — not bcrypt —
  is the right primitive here: keys are 32-byte random secrets with no
  entropy to brute-force, and validation must be an indexed exact-match
  lookup. No new dependency is required.)
- Validation runs BEFORE any user/org identity is known, so the RLS SELECT
  policy on ``organization_api_keys`` is permissive for the app role; writes
  are restricted to org admins at both the RLS and the API layer.
- After a successful validation the request's RLS identity (``app.user_id``
  GUC) is stamped as the org owner so gateway writes satisfy the
  owner-scoped policies on ``events``/``alerts``.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import UnauthorizedError
from app.db.models import Organization, OrganizationAPIKey
from app.db.session import current_user_id, get_db

logger = logging.getLogger("cyberguard.api_keys")

API_KEY_PREFIX = "cg_live_"


def hash_api_key(raw_key: str) -> str:
    """SHA-256 hex digest of the raw key (stored in ``key_hash``)."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> str:
    """``cg_live_<43 url-safe chars>`` — ~256 bits of entropy."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


async def create_api_key(
    db: AsyncSession,
    *,
    organization_id: str,
    name: str,
    expires_at: Optional[datetime] = None,
    created_by: Optional[str] = None,
) -> dict[str, Any]:
    """Create an API key. Returns the plaintext ONCE — never store or log it."""
    raw_key = generate_api_key()
    api_key = OrganizationAPIKey(
        organization_id=organization_id,
        name=name,
        key_hash=hash_api_key(raw_key),
        key_prefix=raw_key[:16],
        expires_at=expires_at,
        created_by=created_by,
    )
    db.add(api_key)
    await db.commit()
    return {
        "id": api_key.id,
        "key": raw_key,
        "prefix": api_key.key_prefix,
        "name": name,
        "expires_at": expires_at,
    }


async def validate_api_key(db: AsyncSession, raw_key: str) -> Optional[Organization]:
    """Resolve an ``org_authorization`` header value to an active Organization.

    Returns None when the key is unknown, revoked, expired, or the org is
    suspended. On success, stamps the request's RLS identity as the org owner
    (see module docstring).
    """
    if not raw_key:
        return None
    raw_key = raw_key.strip()
    if raw_key.lower().startswith("bearer "):
        raw_key = raw_key[7:].strip()

    result = await db.execute(
        select(OrganizationAPIKey).where(OrganizationAPIKey.key_hash == hash_api_key(raw_key))
    )
    api_key = result.scalar_one_or_none()
    if api_key is None or api_key.status != "active":
        return None

    now = datetime.now(timezone.utc)
    if api_key.expires_at is not None:
        expires_at = api_key.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < now:
            return None

    org = await db.get(Organization, api_key.organization_id)
    if org is None or org.status != "active":
        return None

    # Close the read-only transaction, then touch last_used_at under the org
    # owner's RLS identity (the admin-write policy needs the GUC). Telemetry
    # only — never fail authentication because of it.
    await db.commit()
    current_user_id.set(org.owner_id)
    try:
        api_key.last_used_at = now
        await db.commit()
    except Exception as exc:  # noqa: BLE001 - last_used_at is best-effort
        await db.rollback()
        logger.debug("could not update last_used_at for key %s: %s", api_key.key_prefix, exc)

    return org


async def get_org_from_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Organization:
    """FastAPI dependency: authenticate a server-to-server request via the
    ``org_authorization`` header and return the key's organization."""
    raw_key = request.headers.get("org_authorization") or ""
    if not raw_key:
        raise UnauthorizedError("Missing org_authorization header")
    org = await validate_api_key(db, raw_key)
    if org is None:
        raise UnauthorizedError("Invalid or expired API key")
    return org
