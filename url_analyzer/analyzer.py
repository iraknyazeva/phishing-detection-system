# url_analyzer/analyzer.py
import sqlite3
from typing import Any, Dict

from .ssl_checker import check_ssl
from .whois_checker import check_whois
from .dns_checker import check_dns
from .url_features import extract_url_features
from .risk_engine import RiskEngine

DB_PATH = "database/phishing.db"


class UrlAnalyzer:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.risk_engine = RiskEngine(self.conn)

    def analyze(self, url: str) -> Dict[str, Any]:
        # 1. Фичи из самого URL (строка, домен, длины и т.п.)
        url_info = extract_url_features(url)
        domain = url_info["domain"]
        scheme = url_info["scheme"]

        # 2. Низкоуровневые проверки
        dns_info = check_dns(domain)
        ssl_info: Dict[str, Any] = {}
        if scheme == "https":
            ssl_info = check_ssl(domain)
        whois_info = check_whois(domain)

        # 3. Индикаторы из БД (чёрный / серый список доменов)
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT * FROM indicators
            WHERE type = 'domain'
              AND value = ?
              AND is_active = 1
              AND is_whitelisted = 0
            """,
            (domain,),
        )
        indicators = [dict(row) for row in cur.fetchall()]

        # 4. Собираем общий словарь features для RiskEngine
        features: Dict[str, Any] = {}

        # URL-признаки
        features.update(url_info["features"])

        # DNS-признаки
        features["dns_resolvable"] = dns_info.get("resolvable", False)
        features["dns_ping_success"] = dns_info.get("ping_success", False)

        # SSL-признаки
        features["ssl_valid"] = ssl_info.get("valid", False) if ssl_info else False
        features["ssl_days_left"] = ssl_info.get("days_left", 0) if ssl_info else 0

        # WHOIS-признаки
        features["whois_age_days"] = whois_info.get("age_days", 0)

        # Индикаторы
        features["indicator_count"] = len(indicators)
        features["indicator_max_risk"] = max(
            (ind.get("risk_score", 0) for ind in indicators),
            default=0,
        )

        # 5. Оценка риска по правилам из risk_rules
        risk_score, status = self.risk_engine.calculate(features, applies_to="url")

        # 6. Возвращаем всё в одном объекте
        return {
            "url": url,
            "domain": domain,
            "risk_score": round(risk_score, 1),
            "status": status,
            "features": features,
            "dns": dns_info,
            "ssl": ssl_info,
            "whois": whois_info,
            "matched_indicators": indicators,
        }
