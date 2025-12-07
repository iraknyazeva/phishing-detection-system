# url_analyzer/risk_engine.py
from __future__ import annotations

from typing import Any, Dict, Tuple
import sqlite3

STATUS_ORDER = ["clean", "suspicious", "malicious"]


class RiskEngine:
    """
    Считает итоговый risk_score и статус на основе признаков (features)
    и правил из таблицы risk_rules.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _load_rules(self, applies_to: str) -> list[Dict[str, Any]]:
        """
        Загружаем все активные правила для заданного типа объекта
        (url / email / both).
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT feature, operator, value, risk_points, status_override
            FROM risk_rules
            WHERE is_active = 1
              AND (applies_to = ? OR applies_to = 'both')
            """,
            (applies_to,),
        )
        rows = cur.fetchall()
        # sqlite row -> dict
        return [dict(row) for row in rows]

    def _max_status(self, current: str, new: str | None) -> str:
        if not new:
            return current
        try:
            if STATUS_ORDER.index(new) > STATUS_ORDER.index(current):
                return new
        except ValueError:
            # если в БД записали что-то странное — игнорируем
            pass
        return current

    def _match_rule(self, rule: Dict[str, Any], features: Dict[str, Any]) -> bool:
        fname = rule["feature"]
        op = rule["operator"]
        rule_val = rule["value"]

        if fname not in features:
            return False

        value = features[fname]

        # булевые операторы
        if op == "is_true":
            return bool(value) is True
        if op == "is_false":
            return bool(value) is False

        # числовые операторы
        try:
            num = float(value)
            thr = float(rule_val) if rule_val is not None else 0.0
        except (TypeError, ValueError):
            # если не смогли привести к числу — правило не срабатывает
            return False

        if op == "lt":
            return num < thr
        if op == "le":
            return num <= thr
        if op == "gt":
            return num > thr
        if op == "ge":
            return num >= thr
        if op == "eq":
            return num == thr

        return False

    def calculate(
        self,
        features: Dict[str, Any],
        applies_to: str = "url",
    ) -> Tuple[float, str]:
        """
        features – словарь вида {"whois_age_days": 10, "ssl_valid": False, ...}
        applies_to – "url" или "email".
        """
        rules = self._load_rules(applies_to)
        score = 0.0
        status = "clean"

        for rule in rules:
            if self._match_rule(rule, features):
                score += float(rule["risk_points"])
                status = self._max_status(status, rule.get("status_override"))

        # Fallback, если ни одно правило не подняло статус
        if status == "clean":
            if score >= 7:
                status = "malicious"
            elif score >= 3:
                status = "suspicious"

        return score, status
