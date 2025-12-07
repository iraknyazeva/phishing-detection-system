from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./database/phishing.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Сначала создаём Base
Base = declarative_base()
metadata = MetaData()

# Функции
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    # 1️⃣ СНАЧАЛА импортируем все модули с моделями
    from database.models import (
        user,
        indicator,
        url_analysis,
        email_analysis,
        external_feeds,
        system_logs,
        notifications,
        settings,
        analysis_sessions,
        risk_rules,
    )

    # 2️⃣ И только потом создаём таблицы
    Base.metadata.create_all(bind=engine)