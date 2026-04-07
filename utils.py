import re
import math
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict


URL_PATTERN = re.compile(
    r"^(https?://)"  # enforce scheme after normalization
    r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"  # basic domain validation
    r"(:\d+)?"
    r"(/[\w\-./?%&=+#:]*)?$"
)


def utc_timestamp() -> str:
    """Return ISO-8601 UTC timestamp for audit logs and API responses."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def normalize_url(url: str) -> str:
    """Add default scheme to improve user-input compatibility."""
    cleaned = url.strip()
    if not cleaned:
        return cleaned

    parsed = urlparse(cleaned)
    if not parsed.scheme:
        cleaned = f"https://{cleaned}"
    return cleaned


def is_valid_url(url: str) -> bool:
    """Validate normalized URL with regex."""
    if not url:
        return False
    return bool(URL_PATTERN.match(url))


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)


def extract_url_features(url: str) -> Dict[str, float]:
    """Extract structural and content-based features from a URL."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        hostname, path, query = "", "", ""

    features = {
        "url_length": float(len(url)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(path)),
        "query_length": float(len(query)),
        "num_dots": float(url.count(".")),
        "num_hyphens": float(url.count("-")),
        "num_underscores": float(url.count("_")),
        "num_slashes": float(url.count("/")),
        "num_at": float(url.count("@")),
        "num_question": float(url.count("?")),
        "num_equal": float(url.count("=")),
        "num_ampersand": float(url.count("&")),
        "num_digits": float(sum(c.isdigit() for c in url)),
        "digit_ratio": float(sum(c.isdigit() for c in url) / len(url)) if len(url) > 0 else 0.0,
        "hostname_entropy": calculate_entropy(hostname),
        "subdomain_count": float(max(0, hostname.count(".") - 1)),
        "is_https": 1.0 if parsed.scheme == "https" else 0.0,
    }

    # Suspicious keywords presence
    keywords = ["login", "verify", "secure", "account", "update", "bank", "signin", "password", "webscr", "ebayisapi"]
    for word in keywords:
        features[f"has_{word}"] = 1.0 if word in url.lower() else 0.0

    return features
