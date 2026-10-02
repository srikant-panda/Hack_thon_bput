"""Payload-file loading for `ship-once`.

Accepted JSON formats:
- a list of {"action": ..., "data": ...} objects (optional "name" label)
- an object mapping {"<action>": <data>, ...}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_payload_file(path: str) -> list[dict[str, Any]]:
    """Read a payloads JSON file and normalize it to a list of entries."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or "action" not in item:
                raise ValueError(
                    f"payload list entries must be objects with an 'action' key: {item!r}"
                )
            entries.append(item)
    elif isinstance(raw, dict):
        for action, data in raw.items():
            entries.append({"action": action, "data": data})
    else:
        raise ValueError("payload file must be a JSON list or object")  # noqa: TRY004
    return entries
