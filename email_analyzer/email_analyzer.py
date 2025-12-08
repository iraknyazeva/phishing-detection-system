# email_analyzer/email_analyzer.py
import sqlite3
from typing import Any, Dict, List

from url_analyzer.risk_engine import RiskEngine  # переиспользуем общий RiskEngine
from .email_features import extract_email_features

DB_PATH = "database/phishing.db"


class EmailAnalyzer:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.risk_engine = RiskEngine(self.conn)

    def _load_indicators_for_email(
        self,
        from_domain: str,
        urls: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Ищем индикаторы:
        - по домену отправителя (type='domain')
        - по полным URL в письме (type='url')
        """
        cur = self.conn.cursor()
        indicators: List[Dict[str, Any]] = []

        # по домену
        if from_domain:
            cur.execute(
                """
                SELECT * FROM indicators
                WHERE type = 'domain'
                  AND value = ?
                  AND is_active = 1
                  AND is_whitelisted = 0
                """,
                (from_domain,),
            )
            indicators.extend(dict(row) for row in cur.fetchall())

        # по URL
        if urls:
            cur.execute(
                f"""
                SELECT * FROM indicators
                WHERE type = 'url'
                  AND value IN ({",".join("?" for _ in urls)})
                  AND is_active = 1
                  AND is_whitelisted = 0
                """,
                urls,
            )
            indicators.extend(dict(row) for row in cur.fetchall())

        return indicators

    def analyze(self, eml_text: str) -> Dict[str, Any]:
        # 1. Разобрать письмо и вытащить фичи
        email_info = extract_email_features(eml_text)
        headers = email_info["headers"]
        body_text = email_info["body_text"]
        urls = email_info["urls"]
        base_features = email_info["features"]

        from_domain = headers.get("from_domain", "")

        # 2. Индикаторы (домены/URL внутри письма)
        indicators = self._load_indicators_for_email(from_domain, urls)

        # 3. Собираем общий словарь features для RiskEngine
        features: Dict[str, Any] = {}
        features.update(base_features)

        features["email_indicator_count"] = len(indicators)
        features["email_indicator_max_risk"] = max(
            (ind.get("risk_score", 0) for ind in indicators),
            default=0,
        )

        # Можно добавить ещё: количество URL в письме, которые сами по себе фишинговые,
        # если ты будешь гонять их через UrlAnalyzer. Пока оставим как TODO.

        # 4. Оценка риска по правилам (applies_to='email')
        risk_score, status = self.risk_engine.calculate(features, applies_to="email")

        # 5. Возвращаем всё
        return {
            "headers": headers,
            "body_text": body_text,
            "urls": urls,
            "features": features,
            "risk_score": round(risk_score, 1),
            "status": status,
            "matched_indicators": indicators,
        }
