# url_analyzer/url_features.py
import urllib.parse
import re
from typing import Dict, Any


IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Парсит URL и возвращает:
    - домен, схему, путь
    - простые признаки/фичи для RiskEngine
    """
    parsed = urllib.parse.urlparse(url)

    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    path = parsed.path or "/"
    query = parsed.query or ""

    domain = host

    # Признаки по домену/URL (без оценки риска!)
    features: Dict[str, Any] = {}

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    features["domain_has_at"] = "@" in domain
    features["domain_has_digit"] = any(ch.isdigit() for ch in domain)
    features["domain_is_ip"] = bool(IP_REGEX.match(domain))
    features["domain_dot_count"] = domain.count(".")
    features["domain_dash_count"] = domain.count("-")

    suspicious_keywords = ["login", "secure", "update", "verify", "account"]
    lower_domain = domain.lower()
    features["domain_has_suspicious_keyword"] = any(
        kw in lower_domain for kw in suspicious_keywords
    )

    return {
        "url": url,
        "scheme": scheme,
        "domain": domain,
        "path": path,
        "features": features,
    }
