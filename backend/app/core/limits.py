"""Global pipeline limits and quotas for real-time email processing."""

from __future__ import annotations

# Maximum size of a single email payload in bytes (10 MB)
MAX_EMAIL_BYTES: int = 10_000_000

# Maximum characters preserved for message body text and HTML (200,000 chars)
MAX_BODY_CHARS: int = 200_000

# Maximum number of unique URLs extracted per message
MAX_URLS: int = 100

# Maximum MIME parts processed before truncation
MAX_MIME_PARTS: int = 100

# Network timeout in seconds for fetching email message from Gmail API
FETCH_TIMEOUT_S: int = 30

# Maximum number of attachment metadata objects stored
MAX_ATTACHMENT_META: int = 20
