from database.init_db import init_database
from database.database import SessionLocal
from database.repositories.threat_repository import ThreatRepository


def test_all_functionality():
    print("Testing COMPLETE database functionality...")

    # 1. Инициализируем БД и создаём все таблицы
    init_database()

    # 2. Проверяем работу репозитория
    db = SessionLocal()
    try:
        repo = ThreatRepository(db)

        # 3. Проверяем все нужные методы
        print("Testing find_by_value...")
        indicator = repo.find_by_value("evil-phishing.com")
        assert indicator is not None

        print("Testing get_all...")
        indicators = repo.get_all()
        assert len(indicators) > 0

        print("Testing get_high_risk_indicators...")
        high_risk = repo.get_high_risk_indicators()
        assert len(high_risk) > 0

        print("Testing to_dict conversion...")
        indicator_dict = indicator.to_dict()
        assert isinstance(indicator_dict, dict)

        print("Testing helper methods...")
        assert indicator.is_high_risk() is True

        print(
            "Database contains: "
            "indicators, url_analysis, email_analysis, "
            "external_feeds, system_logs, notifications, system_settings"
        )
    finally:
        db.close()


if __name__ == "__main__":
    test_all_functionality()
