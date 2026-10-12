from __future__ import annotations

import re

_LIVE = re.compile(
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|\bsk_(?:live|test)_[A-Za-z0-9]{6,}\b"
    r"|Bearer\s+[A-Za-z0-9._\-]{12,}"
    r"|[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}",
    re.IGNORECASE,
)


def looks_live_secret(value: str) -> bool:
    return bool(_LIVE.search(value))


def redact_text(value: str) -> str:
    return _LIVE.sub("«redacted»", value)
