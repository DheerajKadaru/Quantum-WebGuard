import ipaddress
import re
from urllib.parse import urlparse


class RuleEngine:
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
        re.compile(r"///+"),
        re.compile(r"[0-9a-fA-F]{12,}"),
    ]

    TRUSTED_DOMAINS = {
        "google.com",
        "youtube.com",
        "whatsapp.com",
        "facebook.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "netflix.com",
        "instagram.com",
        "twitter.com",
        "linkedin.com",
        "campx.in", # Added based on user case
    }

    def classify(self, url: str) -> dict:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        full_url = url.lower()
        suspicious_segment = f"{parsed.path or ''}?{parsed.query or ''}"

        # 0. Trusted Domain Early-Exit
        # Check if the domain itself is a trusted one (or ends with it)
        is_trusted = any(hostname == d or hostname.endswith(f".{d}") for d in self.TRUSTED_DOMAINS)
        if is_trusted:
            return {
                "prediction": "Safe",
                "attack_type": "None",
                "risk_score": 0.0,
                "source": "Trusted Domain",
                "reasoning": f"Domain '{hostname}' is on our global trusted allowlist."
            }

        # 1. Rule-Based Override (Highest Priority)
        # BUG FIX: Restrict "0 or 1" check only to the hostname to avoid path false positives
        if "0" in hostname or "1" in hostname:
            return {
                "prediction": "Unsafe",
                "attack_type": "Domain Spoofing",
                "risk_score": 100.0,
                "source": "Rule-Based",
                "reasoning": f"Hostname '{hostname}' contains suspicious numeric character '0' or '1' (common spoofing pattern)."
            }

        risk_score = 0.0
        attack_type = "None"
        reasoning = []

        if parsed.scheme != "https":
            risk_score += 15
            attack_type = "Insecure Protocol"
            reasoning.append("Insecure HTTP protocol used.")

        if self._is_ip_host(hostname):
            risk_score += 40
            attack_type = "Suspicious IP"
            reasoning.append("Hostname is a direct IP address.")

        if any(pattern.search(suspicious_segment) for pattern in self.OBFUSCATION_PATTERNS):
            risk_score += 30
            attack_type = "URL Obfuscation"
            reasoning.append("Detected URL obfuscation patterns (e.g., @ symbol or multiple slashes).")

        if self._contains_tokens(full_url, self.PHISHING_KEYWORDS):
            risk_score += 35
            attack_type = "Phishing"
            reasoning.append("Contains phishing-related keywords (e.g., login, verify, secure).")

        if self._contains_tokens(full_url, self.MALWARE_KEYWORDS):
            risk_score += 35
            attack_type = "Malware Distribution"
            reasoning.append("Contains malware-related keywords.")

        if self._is_domain_spoofing(hostname):
            risk_score += 40
            attack_type = "Domain Spoofing"
            reasoning.append("Hostname attempts to mimic a well-known domain.")

        if self._is_dga_like(hostname):
            risk_score += 25
            attack_type = "DGA-like Domain"
            reasoning.append("Hostname looks like a machine-generated string (DGA).")

        if hostname in self.SHORTENER_DOMAINS:
            risk_score += 15
            reasoning.append("Uses a known URL shortener service.")

        risk_score = min(100.0, risk_score)
        # We classify as Malicious if risk score is high, but this is the "Heuristic" layer
        prediction = "Malicious" if risk_score >= 50 else "Safe"
        
        reasoning_str = " ".join(reasoning) if reasoning else "No suspicious structural patterns found."

        return {
            "prediction": prediction,
            "attack_type": attack_type,
            "risk_score": float(risk_score),
            "source": "Heuristic Fallback",
            "reasoning": reasoning_str
        }

    @staticmethod
    def _contains_tokens(url: str, tokens: set[str]) -> bool:
        return any(token in url for token in tokens)

    @staticmethod
    def _is_ip_host(hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

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
