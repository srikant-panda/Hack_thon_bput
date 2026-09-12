"""Fernet-based encryption for email-connector provider tokens.

Tokens are encrypted at rest with the ``CONNECTOR_TOKEN_KEY`` env value
(Fernet key). Plaintext tokens never appear in logs, responses, or the
database — only in runtime variables while a provider call executes.
"""

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

_MASK_KEEP = 4


def _get_fernet() -> Fernet:
    key = get_settings().CONNECTOR_TOKEN_KEY
    if not key:
        raise RuntimeError("CONNECTOR_TOKEN_KEY is required for email connectors")
    try:
        return Fernet(key.encode())
    except Exception as exc:  # noqa: BLE001 - surface key-format problems clearly
        raise RuntimeError(
            "CONNECTOR_TOKEN_KEY is not a valid Fernet key. Generate one with: "
            'uv run python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        ) from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a provider token for storage. Raises without CONNECTOR_TOKEN_KEY."""
    if plaintext is None:
        raise ValueError("Cannot encrypt None secret")
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored provider token. Raises without CONNECTOR_TOKEN_KEY."""
    if not ciphertext:
        raise ValueError("Cannot decrypt empty ciphertext")
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(
            "Stored connector token cannot be decrypted — CONNECTOR_TOKEN_KEY "
            "changed or the stored value is corrupt. Disconnect and reconnect "
            "the affected mailbox."
        ) from exc


def mask_secret(value: str) -> str:
    """Mask a secret for display/logging: ``ya29...abcd``."""
    if not value:
        return ""
    if len(value) <= _MASK_KEEP * 2 + 3:
        return f"{value[:2]}...{value[-2:]}" if len(value) > 4 else "..."
    return f"{value[:_MASK_KEEP]}...{value[-_MASK_KEEP:]}"
