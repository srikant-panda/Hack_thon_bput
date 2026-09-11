"""Operation mode detection for dual-mode (client/server) analysis."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class OperationMode(str, Enum):
    CLIENT = "client"   # analysis only, no enforcement
    SERVER = "server"   # analysis + enforcement via policy engine


class EnforcementPolicyLevel(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class ModeContext(BaseModel):
    """Resolved mode context attached to every analysis request."""
    mode: OperationMode = OperationMode.CLIENT
    policy_level: Optional[EnforcementPolicyLevel] = None
    auto_execute: bool = False
    source: str = "api"

    @property
    def is_server_mode(self) -> bool:
        return self.mode == OperationMode.SERVER


# Sources that imply server mode even if caller forgets to set mode=server
_SERVER_SOURCES = frozenset({
    "email_gateway", "firewall", "proxy", "siem",
    "api_integration", "sso", "network_sensor",
})


def resolve_mode(
    explicit_mode: Optional[str] = None,
    source: Optional[str] = None,
    has_integration_api_key: bool = False,
    policy_level: Optional[str] = None,
    auto_execute: bool = False,
) -> ModeContext:
    """
    Resolve the operation mode for a request.

    Priority:
      1. Explicit `mode` field from request body/header.
      2. Source name that implies server integration.
      3. Presence of an integration API key.
      4. Default to CLIENT.
    """
    mode = OperationMode.CLIENT

    if explicit_mode:
        try:
            mode = OperationMode(explicit_mode.lower())
        except ValueError:
            mode = OperationMode.CLIENT
    elif source and source.lower() in _SERVER_SOURCES:
        mode = OperationMode.SERVER
    elif has_integration_api_key:
        mode = OperationMode.SERVER

    resolved_policy: Optional[EnforcementPolicyLevel] = None
    if policy_level:
        try:
            resolved_policy = EnforcementPolicyLevel(policy_level.lower())
        except ValueError:
            resolved_policy = None

    return ModeContext(
        mode=mode,
        policy_level=resolved_policy,
        auto_execute=auto_execute if mode == OperationMode.SERVER else False,
        source=source or "api",
    )
