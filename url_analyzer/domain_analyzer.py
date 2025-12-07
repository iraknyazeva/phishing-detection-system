# url_analyzer/domain_analyzer.py
import urllib.parse
from typing import Any, Dict

from .dns_checker import check_dns
from .ssl_checker import check_ssl
from .whois_checker import check_whois
from .rules import is_valid_domain_format, apply_basic_url_rules


def analyze_domain(url: str) -> Dict[str, Any]:
    """
    Анализ домена и базовых URL-характеристик.
    НИКАКОГО доступа к БД, только внешние проверки + эвристики URL.
    """
    parsed = urllib.parse.urlparse(url)

    scheme = parsed.scheme or "http"
    # hostname предпочтительнее, но на всякий случай fallback на netloc
    domain = parsed.hostname or parsed.netloc
    path = parsed.path or "/"

    # 1. Формат домена и базовые URL-правила
    domain_valid = is_valid_domain_format(domain)
    url_violations = apply_basic_url_rules(
        scheme=scheme,
        domain=domain,
        path=path,
        domain_valid=domain_valid,
    )

    # 2. DNS
    dns_info = check_dns(domain)

    # 3. SSL (только для https)
    ssl_info = {}
    if scheme == "https":
        ssl_info = check_ssl(domain)

    # 4. WHOIS
    whois_info = check_whois(domain)

    # 5. Признаки для RiskEngine
    features = {
        "dns_resolvable": dns_info.get("resolvable", False),
        "dns_ping_success": dns_info.get("ping_success", False),
        "ssl_valid": ssl_info.get("valid", False) if ssl_info else False,
        "ssl_days_left": ssl_info.get("days_left", 0) if ssl_info else 0,
        "whois_age_days": whois_info.get("age_days", 0),
        "url_violation_count": len(url_violations),
        "domain_valid": domain_valid,
    }

    return {
        "url": url,
        "scheme": scheme,
        "domain": domain,
        "path": path,
        "dns": dns_info,
        "ssl": ssl_info,
        "whois": whois_info,
        "url_violations": url_violations,
        "features": features,
    }
