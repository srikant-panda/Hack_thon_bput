"""In-memory MockEmailProvider (Phase 6).

Implements the full 14-method contract against in-memory state with
configurable failure flags. Purpose: prove the security engine relies only on
the EmailProvider contract — swap Gmail for the mock and every code path
still works. Test/demo use only; never registered for real connections.
"""

import base64
import uuid
from datetime import datetime, timezone

from app.services.email_providers.base import (
    EmailProviderError,
    ProviderCapability,
    ProviderErrorClass,
)


class MockEmailProvider:
    provider = "mock"
    quarantine_label_name = "CYBERGUARD-Quarantine"

    _capability = ProviderCapability(
        read_messages=True,
        read_attachments=True,
        modify_labels=True,
        quarantine=True,
        trash=True,
        permanent_delete=True,
        sender_rules=True,
        send_mail=True,
    )

    def __init__(
        self,
        *,
        fail_quarantine: bool = False,
        fail_sender_rules: bool = False,
        fail_refresh: bool = False,
        supports_sender_rules: bool = True,
        supports_permanent_delete: bool = True,
    ):
        self.fail_quarantine = fail_quarantine
        self.fail_sender_rules = fail_sender_rules
        self.fail_refresh = fail_refresh
        self._supports_sender_rules = supports_sender_rules
        self._supports_permanent_delete = supports_permanent_delete
        self.calls: list[tuple] = []
        self.state: dict = {
            "labels": {self.quarantine_label_name: "Label_Q"},
            "messages": {},   # id -> {labels: [...], trashed: bool, deleted: bool, raw: str}
            "filters": {},    # rule_id -> {from, label}
            "drafts": {},
            "attachments": {},  # (message_id, attachment_id) -> {data, size}
        }

    @property
    def capabilities(self) -> dict:
        return ProviderCapability(
            read_messages=True,
            read_attachments=True,
            modify_labels=True,
            quarantine=True,
            trash=True,
            permanent_delete=self._supports_permanent_delete,
            sender_rules=self._supports_sender_rules,
            send_mail=True,
        ).flags()

    def seed_message(self, message_id: str, *, sender: str = "seed@example.test") -> None:
        self.state["messages"][message_id] = {
            "id": message_id,
            "labels": ["INBOX"],
            "trashed": False,
            "deleted": False,
            "raw": f"From: {sender}\r\nSubject: seed\r\n\r\nbody",
            "sender": sender,
        }

    # --- 1. authorization lifecycle ---
    async def authorize(self, *, redirect_uri: str, state: str) -> dict:
        self.calls.append(("authorize", redirect_uri, state))
        return {"authorization_url": f"https://mock.example.test/oauth?state={state}&redirect={redirect_uri}"}

    async def refresh_token(self, refresh_token: str) -> dict:
        self.calls.append(("refresh_token", refresh_token))
        if self.fail_refresh:
            raise EmailProviderError(ProviderErrorClass.REAUTH_REQUIRED, "Mock refresh rejected.")
        return {"access_token": f"mock-access-{uuid.uuid4().hex[:8]}", "expires_in": 3600}

    # --- 2. reading ---
    async def list_messages(self, access_token: str, max_results: int = 50) -> list[dict]:
        self.calls.append(("list_messages", max_results))
        ids = [mid for mid, m in self.state["messages"].items() if not m["deleted"]][:max_results]
        return [{"id": mid, "thread_id": mid} for mid in ids]

    async def get_message(self, access_token: str, message_id: str) -> dict:
        self.calls.append(("get_message", message_id))
        message = self.state["messages"].get(message_id)
        if message is None or message["deleted"]:
            raise EmailProviderError(ProviderErrorClass.FAILED, f"Mock message {message_id} not found.")
        return {
            "id": message_id,
            "thread_id": message_id,
            "labelIds": message["labels"],
            "internalDate": str(int(datetime.now(timezone.utc).timestamp() * 1000)),
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": message["sender"]},
                    {"name": "To", "value": "victim@example.test"},
                    {"name": "Subject", "value": "Mock message"},
                ],
                "body": {"data": base64.urlsafe_b64encode(b"mock body").decode().rstrip("=")},
            },
        }

    async def get_attachment(self, access_token: str, message_id: str, attachment_id: str) -> dict:
        self.calls.append(("get_attachment", message_id, attachment_id))
        attachment = self.state["attachments"].get((message_id, attachment_id))
        if attachment is None:
            raise EmailProviderError(ProviderErrorClass.FAILED, "Mock attachment not found.")
        return {"attachmentId": attachment_id, "data": attachment["data"], "size": attachment["size"]}

    # --- 3. composing ---
    async def create_draft(self, access_token: str, raw_mime: str, thread_id: str | None = None) -> dict:
        draft_id = f"draft-{uuid.uuid4().hex[:8]}"
        self.calls.append(("create_draft", draft_id))
        self.state["drafts"][draft_id] = {"raw": raw_mime, "thread_id": thread_id}
        return {"id": draft_id}

    async def send_message(self, access_token: str, raw_mime: str, thread_id: str | None = None) -> dict:
        message_id = f"sent-{uuid.uuid4().hex[:8]}"
        self.calls.append(("send_message", message_id))
        self.state["messages"][message_id] = {
            "id": message_id, "labels": ["SENT"], "trashed": False,
            "deleted": False, "raw": raw_mime, "sender": "me@mock.test",
        }
        return {"id": message_id}

    # --- 4. message actions ---
    async def modify_message(self, access_token: str, message_id: str,
                             add_label_ids: list[str] | None = None,
                             remove_label_ids: list[str] | None = None) -> dict:
        self.calls.append(("modify_message", message_id, add_label_ids, remove_label_ids))
        message = self.state["messages"].get(message_id)
        if message is None:
            raise EmailProviderError(ProviderErrorClass.FAILED, f"Mock message {message_id} not found.")
        for label in add_label_ids or []:
            if label not in message["labels"]:
                message["labels"].append(label)
        for label in remove_label_ids or []:
            if label in message["labels"]:
                message["labels"].remove(label)
        return {"id": message_id, "labelIds": message["labels"]}

    async def move_to_trash(self, access_token: str, message_id: str) -> dict:
        self.calls.append(("move_to_trash", message_id))
        message = self.state["messages"].get(message_id)
        if message is None:
            raise EmailProviderError(ProviderErrorClass.FAILED, f"Mock message {message_id} not found.")
        message["trashed"] = True
        return {"id": message_id, "trashed": True}

    async def delete_message(self, access_token: str, message_id: str, permanent: bool) -> dict:
        self.calls.append(("delete_message", message_id, permanent))
        message = self.state["messages"].get(message_id)
        if message is None:
            raise EmailProviderError(ProviderErrorClass.FAILED, f"Mock message {message_id} not found.")
        if permanent:
            if not self._supports_permanent_delete:
                raise EmailProviderError(ProviderErrorClass.INSUFFICIENT_SCOPE, "Mock provider lacks permanent delete.")
            message["deleted"] = True
            return {"deleted": True, "permanent": True}
        message["trashed"] = True
        return {"id": message_id, "trashed": True}

    async def quarantine_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict:
        self.calls.append(("quarantine_message", message_id, quarantine_label))
        if self.fail_quarantine:
            raise EmailProviderError(ProviderErrorClass.INSUFFICIENT_SCOPE, "Mock quarantine denied.")
        return await self.modify_message(
            access_token, message_id, add_label_ids=[quarantine_label], remove_label_ids=["INBOX"]
        )

    async def release_message(self, access_token: str, message_id: str, quarantine_label: str) -> dict:
        self.calls.append(("release_message", message_id, quarantine_label))
        return await self.modify_message(
            access_token, message_id, add_label_ids=["INBOX"], remove_label_ids=[quarantine_label]
        )

    # --- 5. sender rules ---
    async def create_sender_rule(self, access_token: str, sender_email: str, target_label: str) -> dict:
        self.calls.append(("create_sender_rule", sender_email, target_label))
        if self.fail_sender_rules or not self._supports_sender_rules:
            raise EmailProviderError(ProviderErrorClass.INSUFFICIENT_SCOPE, "Mock sender rules denied.")
        rule_id = f"mock-filter-{uuid.uuid4().hex[:6]}"
        self.state["filters"][rule_id] = {"from": sender_email, "label": target_label}
        return {"id": rule_id}

    async def update_sender_rule(self, access_token: str, rule_id: str, sender_email: str, target_label: str) -> dict:
        self.calls.append(("update_sender_rule", rule_id, sender_email, target_label))
        if rule_id not in self.state["filters"]:
            raise EmailProviderError(ProviderErrorClass.FAILED, f"Mock filter {rule_id} not found.")
        self.state["filters"][rule_id] = {"from": sender_email, "label": target_label}
        return {"rule_id": rule_id, "updated": True}

    async def delete_sender_rule(self, access_token: str, rule_id: str) -> dict:
        self.calls.append(("delete_sender_rule", rule_id))
        if self.fail_sender_rules:
            raise EmailProviderError(ProviderErrorClass.INSUFFICIENT_SCOPE, "Mock sender rules denied.")
        self.state["filters"].pop(rule_id, None)
        return {"deleted": True, "rule_id": rule_id}

    # --- operational extensions ---
    async def get_profile(self, access_token: str) -> dict:
        return {"email_address": "mock-user@mock.test", "messages_total": len(self.state["messages"])}

    async def test_connection(self, access_token: str) -> dict:
        return {"provider": self.provider, "email_address": "mock-user@mock.test", "ok": True}

    async def ensure_quarantine_label(self, access_token: str) -> str:
        self.calls.append(("ensure_quarantine_label",))
        return self.state["labels"].setdefault(self.quarantine_label_name, "Label_Q")


mock_provider = MockEmailProvider()
