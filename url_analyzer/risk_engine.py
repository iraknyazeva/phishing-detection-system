# url_analyzer/risk_engine.py
from __future__ import annotations

from typing import Any, Dict, Tuple
import sqlite3

STATUS_ORDER = ["clean", "suspicious", "malicious"]


class RiskEngine:
    """
    Берёт features + правила из таблицы risk_rules и считает risk_score и статус.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _load_rules(self, applies_to: str) -> list[Dict[str, Any]]:
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
        return [dict(row) for row in rows]

    def _max_status(self, current: str, new: str | None) -> str:
        if not new:
            return current
        try:
            if STATUS_ORDER.index(new) > STATUS_ORDER.index(current):
                return new
        except ValueError:
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
        rules = self._load_rules(applies_to)
        score = 0.0
        status = "clean"

        for rule in rules:
            if self._match_rule(rule, features):
                score += float(rule["risk_points"])
                status = self._max_status(status, rule.get("status_override"))

        # Fallback, если статус не выставили
        if status == "clean":
            if score >= 7:
                status = "malicious"
            elif score >= 3:
                status = "suspicious"

        return score, status
