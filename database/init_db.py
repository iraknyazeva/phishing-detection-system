from database.database import create_tables, SessionLocal
from database.repositories.threat_repository import ThreatRepository
from database.models.settings import SystemSetting

def init_database():
    # 1️⃣ Создаём таблицы
    create_tables()
    print("✅ All tables created successfully!")

    db = SessionLocal()

    # 2️⃣ Загружаем тестовые индикаторы
    repo = ThreatRepository(db)
    if repo.load_initial_indicators():
        indicators = repo.get_all()
        print(f"✅ Loaded {len(indicators)} initial indicators")
    else:
        print("❌ Failed to load initial indicators")

    # 3️⃣ Создаём базовые настройки
    default_settings = [
        {"key": "analysis.risk_threshold.suspicious", "value": "3.0", "value_type": "float", "category": "analysis"},
        {"key": "analysis.risk_threshold.malicious", "value": "7.0", "value_type": "float", "category": "analysis"},
        {"key": "notifications.enabled", "value": "true", "value_type": "boolean", "category": "notifications"},
    ]

    for setting_data in default_settings:
        existing = db.query(SystemSetting).filter(SystemSetting.key == setting_data["key"]).first()
        if not existing:
            setting = SystemSetting(**setting_data)
            db.add(setting)

    db.commit()
    print("✅ Default settings created")
    db.close()

if __name__ == "__main__":
    init_database()
