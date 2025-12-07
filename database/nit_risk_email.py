import sqlite3

DB_PATH = "phishing.db"  # если путь другой – поправь здесь
CREATED_BY = 1                    # id пользователя (admin/1 и т.п.)

EMAIL_RULES = [
    # SPF fail → сильно подозрительно
    (
        "SPF fail в письме",                 # name
        "email_spf_fail",                    # feature
        "is_true",                           # operator
        None,                                # value
        4,                                   # risk_points
        "suspicious",                        # status_override
        "email",                             # applies_to
        1,                                   # is_active
        "Проверка SPF не пройдена",         # description
        CREATED_BY,                          # created_by
    ),

    # DKIM fail → +риск
    (
        "DKIM fail в письме",
        "email_dkim_fail",
        "is_true",
        None,
        3,
        None,
        "email",
        1,
        "Подпись DKIM невалидна",
        CREATED_BY,
    ),

    # DMARC fail → ещё сильнее
    (
        "DMARC fail в письме",
        "email_dmarc_fail",
        "is_true",
        None,
        5,
        "suspicious",
        "email",
        1,
        "DMARC-политика не выполняется",
        CREATED_BY,
    ),

    # From и Reply-To разные
    (
        "From и Reply-To отличаются",
        "email_from_reply_mismatch",
        "is_true",
        None,
        3,
        None,
        "email",
        1,
        "Адрес отправителя и адрес для ответа различаются",
        CREATED_BY,
    ),

    # From-домен и Reply-To-домен разные
    (
        "From-домен и Reply-To-домен различаются",
        "email_from_reply_domain_mismatch",
        "is_true",
        None,
        3,
        "suspicious",
        "email",
        1,
        "Домен отправителя и домен для ответа не совпадают",
        CREATED_BY,
    ),

    # Подозрительные слова в теме (urgent/verify/confirm/...)
    (
        "Подозрительные слова в теме письма",
        "email_subject_suspicious_keywords",
        "gt",
        "0",
        2,
        None,
        "email",
        1,
        "В теме есть слова urgent/verify/confirm/пароль/срочно и т.п.",
        CREATED_BY,
    ),

    # Подозрительные фразы в теле (verify your account / подтвердите аккаунт / ...)
    (
        "Подозрительные фразы в теле письма",
        "email_body_suspicious_keywords",
        "gt",
        "0",
        3,
        None,
        "email",
        1,
        "В теле есть фразы типа verify your account / подтвердите свою учетную запись",
        CREATED_BY,
    ),

    # Много ссылок в письме → лёгкий риск
    (
        "Много ссылок в письме",
        "email_url_count",
        "gt",
        "5",
        2,
        None,
        "email",
        1,
        "В письме больше 5 ссылок",
        CREATED_BY,
    ),

    # Любой индикатор → подозрительно
    (
        "Индикаторы в письме",
        "email_indicator_count",
        "gt",
        "0",
        4,
        "suspicious",
        "email",
        1,
        "Найден индикатор угрозы по домену или URL в письме",
        CREATED_BY,
    ),

    # Индикатор высокого риска → сразу malicious
    (
        "Высокорисковые индикаторы в письме",
        "email_indicator_max_risk",
        "ge",
        "7",
        7,
        "malicious",
        "email",
        1,
        "Индикатор с risk_score >= 7 в письме",
        CREATED_BY,
    ),
]


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Проверяем, что таблица risk_rules существует
    cur.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='risk_rules'
        """
    )
    row = cur.fetchone()
    if not row:
        print("❌ Таблица 'risk_rules' не найдена в БД. Убедись, что миграции применены.")
        conn.close()
        return

    inserted = 0

    for rule in EMAIL_RULES:
        (name, feature, operator, value,
         risk_points, status_override, applies_to,
         is_active, description, created_by) = rule

        # Проверяем, есть ли уже такое правило (name + feature + applies_to)
        cur.execute(
            """
            SELECT id FROM risk_rules
            WHERE name = ? AND feature = ? AND applies_to = ?
            """,
            (name, feature, applies_to),
        )
        exists = cur.fetchone()
        if exists:
            print(f"↷ Уже есть: {name} ({feature}, {applies_to}) – пропускаю.")
            continue

        cur.execute(
            """
            INSERT INTO risk_rules
            (name, feature, operator, value, risk_points,
             status_override, applies_to, is_active, description, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rule,
        )
        inserted += 1
        print(f"✔ Добавлено правило: {name} ({feature}, {applies_to})")

    conn.commit()
    conn.close()
    print(f"\nГотово! Добавлено новых email-правил: {inserted}")


if __name__ == "__main__":
    main()
