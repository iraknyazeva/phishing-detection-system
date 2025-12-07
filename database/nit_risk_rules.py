import sqlite3

DB_PATH = "phishing.db"   # если у тебя другой путь к БД – поменяй здесь
CREATED_BY = 1            # id пользователя, который считается создателем правил


RULES = [
    # 5.1 DNS (dns_checker)

    (
        "DNS не резолвится",          # name
        "dns_resolvable",             # feature
        "is_false",                   # operator
        None,                         # value
        6,                            # risk_points
        "suspicious",                 # status_override
        "url",                        # applies_to
        1,                            # is_active
        "Домен не резолвится через DNS",  # description
        CREATED_BY,                   # created_by
    ),
    (
        "Ping не проходит",
        "dns_ping_success",
        "is_false",
        None,
        1,
        None,
        "url",
        1,
        "Ping до домена неудачен",
        CREATED_BY,
    ),

    # 5.2 SSL (ssl_checker)

    (
        "Невалидный SSL",
        "ssl_valid",
        "is_false",
        None,
        4,
        "suspicious",
        "url",
        1,
        "Нет валидного SSL-сертификата",
        CREATED_BY,
    ),
    (
        "Скоро истечёт сертификат",
        "ssl_days_left",
        "lt",
        "7",
        1,
        None,
        "url",
        1,
        "SSL-сертификат истекает менее чем через неделю",
        CREATED_BY,
    ),

    # 5.3 WHOIS (whois_checker)

    (
        "Очень молодой домен",
        "whois_age_days",
        "lt",
        "7",
        5,
        "suspicious",
        "url",
        1,
        "Домены младше 7 дней считаем очень подозрительными",
        CREATED_BY,
    ),
    (
        "Молодой домен",
        "whois_age_days",
        "lt",
        "30",
        3,
        "suspicious",
        "url",
        1,
        "Домены младше 30 дней считаем подозрительными",
        CREATED_BY,
    ),

    # 5.4 Признаки из url_features.py

    (
        "Собачка в домене",
        "domain_has_at",
        "is_true",
        None,
        3,
        "suspicious",
        "url",
        1,
        "В домене присутствует символ @",
        CREATED_BY,
    ),
    (
        "Очень длинный домен",
        "domain_length",
        "gt",
        "60",
        2,
        None,
        "url",
        1,
        "Длина домена больше 60 символов",
        CREATED_BY,
    ),
    (
        "Домен-подобие IP",
        "domain_is_ip",
        "is_true",
        None,
        3,
        "suspicious",
        "url",
        1,
        "Домен выглядит как IP-адрес",
        CREATED_BY,
    ),
    (
        "Подозрительные слова в домене",
        "domain_has_suspicious_keyword",
        "is_true",
        None,
        3,
        None,
        "url",
        1,
        "login/secure/update/verify/account в домене",
        CREATED_BY,
    ),
    (
        "Очень длинный URL",
        "url_length",
        "gt",
        "150",
        1,
        None,
        "url",
        1,
        "Длина URL больше 150 символов",
        CREATED_BY,
    ),

    # 5.5 Индикаторы (чёрный список)

    (
        "Совпадение по индикаторам",
        "indicator_count",
        "gt",
        "0",
        7,
        "malicious",
        "url",
        1,
        "Домен найден в таблице indicators",
        CREATED_BY,
    ),
]


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Проверим, что таблица risk_rules существует
    cur.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='risk_rules'
        """
    )
    row = cur.fetchone()
    if not row:
        print("❌ Таблица risk_rules не найдена в БД. Убедись, что миграции применены.")
        conn.close()
        return

    inserted = 0
    for rule in RULES:
        name, feature, operator, value, risk_points, status_override, applies_to, is_active, description, created_by = rule

        # Проверяем, нет ли уже такого правила (по name + feature)
        cur.execute(
            """
            SELECT id FROM risk_rules
            WHERE name = ? AND feature = ?
            """,
            (name, feature),
        )
        exists = cur.fetchone()
        if exists:
            print(f"↷ Пропускаю (уже есть): {name} / {feature}")
            continue

        cur.execute(
            """
            INSERT INTO risk_rules
            (name, feature, operator, value, risk_points, status_override,
             applies_to, is_active, description, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rule,
        )
        inserted += 1
        print(f"✔ Добавлено правило: {name} ({feature})")

    conn.commit()
    conn.close()
    print(f"\nГотово! Добавлено новых правил: {inserted}")


if __name__ == "__main__":
    main()
