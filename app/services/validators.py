import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"^(https?://)"
    r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"
    r"(:\d+)?"
    r"(/[\w\-./?%&=+#:]*)?$"
)


def normalize_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""

    parsed = urlparse(cleaned)
    if not parsed.scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def is_valid_url(url: str) -> bool:
    return bool(url and URL_PATTERN.match(url))
