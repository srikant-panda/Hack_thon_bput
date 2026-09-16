"""Schemas for Gmail Pub/Sub webhook payloads."""

from pydantic import BaseModel


class GmailSyncJobPayload(BaseModel):
    account_id: str
    history_id: str
