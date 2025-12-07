import sqlite3

DB_PATH = "phishing.db"   # Укажи путь, если лежит в другом месте
CREATED_BY = 1            # id пользователя (обычно admin)

RULE = (
    "Индикатор высокого риска",            # name
    "indicator_max_risk",                  # feature
    "ge",                                   # operator
    "7",                                    # value
    7,                                      # risk_points
    "malicious",                            # status_override
    "url",                                  # applies_to
    1,                                      # is_active
    "Есть индикаторы с risk_score >= 7",    # description
    CREATED_BY                              # created_by
)

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Проверяем наличие правила, чтобы не дублировать
    cur.execute(
        """
        SELECT id FROM risk_rules
        WHERE name = ? AND feature = ?
        """,
        (RULE[0], RULE[1]),
    )
    exists = cur.fetchone()

    if exists:
        print("↷ Правило уже существует, пропускаю.")
    else:
        cur.execute(
            """
            INSERT INTO risk_rules
            (name, feature, operator, value, risk_points,
             status_override, applies_to, is_active, description, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            RULE,
        )
        conn.commit()
        print("✔ Правило 'Индикатор высокого риска' добавлено.")

    conn.close()


if __name__ == "__main__":
    main()
