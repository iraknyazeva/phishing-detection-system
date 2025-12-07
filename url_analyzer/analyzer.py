import sqlite3
from typing import Any, Dict

from .domain_analyzer import analyze_domain
from .page_analyzer import analyze_page
from .risk_engine import RiskEngine

DB_PATH = "phishing.db"


class UrlAnalyzer:
    def __init__(self):
        # Простое подключение к SQLite
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self.risk_engine = RiskEngine(self.conn)

    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Главный метод анализа URL.
        Собирает признаки из подмодулей и считает риск по правилам из таблицы risk_rules.
        """

        # 1. Анализ домена, DNS/SSL/WHOIS и базовых URL-правил
        domain_info = analyze_domain(url)
        domain = domain_info["domain"]

        # 2. Анализ HTML-страницы (если не получится скачать — вернёт error и пустые фичи)
        page_info = analyze_page(url)

        # 3. Поиск индикаторов в БД
        cur = self.conn.cursor()
        cur.execute(
            "SELECT * FROM indicators WHERE type='domain' AND value=?",
            (domain,),
        )
        indicators = [dict(row) for row in cur.fetchall()]

        # 4. Собираем все признаки для RiskEngine
        features: Dict[str, Any] = {}
        features.update(domain_info.get("features", {}))
        features.update(page_info.get("features", {}))
        features["indicator_count"] = len(indicators)

        # 5. Считаем итоговый риск по правилам из таблицы risk_rules
        risk_score, status = self.risk_engine.calculate(features, applies_to="url")

        # 6. Финальный результат
        result = {
            "url": url,
            "domain": domain,
            "risk_score": round(risk_score, 1),
            "status": status,
            "features": features,              # удобно смотреть, что сработало
            "domain_analysis": domain_info,    # DNS/SSL/WHOIS/URL-правила
            "page_analysis": page_info,        # HTML-страница
            "matched_indicators": indicators,  # что нашли в таблице indicators
        }

        return result
