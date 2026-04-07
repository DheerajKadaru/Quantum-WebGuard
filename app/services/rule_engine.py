import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
}

PHISHING_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "bank",
    "signin",
    "password",
}

MALWARE_KEYWORDS = {
    "download",
    "exe",
    "payload",
    "crack",
    "keygen",
    "trojan",
    "ransom",
}

OBFUSCATION_PATTERNS = [
    re.compile(r"%[0-9a-fA-F]{2}"),
    re.compile(r"@"),
    re.compile(r"//+"),
    re.compile(r"[0-9a-fA-F]{12,}"),
]


@dataclass
class RuleResult:
    prediction: str
    attack_type: str
    risk_score: float
    high_risk: bool


class RuleEngine:
    """Rule-based URL risk analyzer for known attack patterns."""

    def classify(self, url: str) -> RuleResult:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        full_url = url.lower()

        risk_score = 0.0
        attack_type = "None"
        high_risk = False

        if parsed.scheme != "https":
            risk_score += 15
            attack_type = "Insecure Protocol"

        if self._is_ip_host(hostname):
            risk_score += 30
            attack_type = "Suspicious IP"
            high_risk = True

        if any(pattern.search(full_url) for pattern in OBFUSCATION_PATTERNS):
            risk_score += 25
            attack_type = "URL Obfuscation"
            high_risk = True

        if self._is_phishing_like(full_url):
            risk_score += 30
            attack_type = "Phishing"
            high_risk = True

        if self._is_malware_like(full_url):
            risk_score += 30
            attack_type = "Malware Distribution"
            high_risk = True

        if self._is_domain_spoofing(hostname):
            risk_score += 25
            attack_type = "Domain Spoofing"
            high_risk = True

        if self._is_dga_like(hostname):
            risk_score += 20
            attack_type = "DGA-like Domain"

        if hostname in SHORTENER_DOMAINS:
            risk_score += 10

        risk_score = min(100.0, risk_score)
        prediction = "Malicious" if risk_score >= 50 else "Safe"

        return RuleResult(
            prediction=prediction,
            attack_type=attack_type,
            risk_score=risk_score,
            high_risk=high_risk,
        )

    @staticmethod
    def _is_ip_host(hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_phishing_like(url: str) -> bool:
        return any(token in url for token in PHISHING_KEYWORDS)

    @staticmethod
    def _is_malware_like(url: str) -> bool:
        return any(token in url for token in MALWARE_KEYWORDS)

    @staticmethod
    def _is_domain_spoofing(hostname: str) -> bool:
        suspicious = ["paypa1", "g00gle", "micr0soft", "faceb00k", "amaz0n"]
        return any(token in hostname for token in suspicious)

    @staticmethod
    def _is_dga_like(hostname: str) -> bool:
        if not hostname:
            return False
        base = hostname.split(".")[0]
        if len(base) < 12:
            return False
        consonant_heavy = re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", base)
        digit_heavy = sum(ch.isdigit() for ch in base) >= 4
        return bool(consonant_heavy or digit_heavy)
