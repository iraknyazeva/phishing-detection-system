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

    # ТОЛЬКО ПОСЛЕ Base импортируем ВСЕ модели
    # (порядок не важен — главное после Base!)
    from database.models.user import User
    from database.models.indicator import Indicator
    from database.models.url_analysis import URLAnalysisResult
    from database.models.email_analysis import EmailAnalysisResult
    from database.models.external_feeds import ExternalFeed
    from database.models.system_logs import SystemLog
    from database.models.notifications import Notification
    from database.models.settings import SystemSetting
    from database.models.analysis_sessions import AnalysisSession
    from database.models.risk_rules import RiskRule

Base.metadata.create_all(bind=engine)