from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./phishing.db"

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
    Base.metadata.create_all(bind=engine)

# ТОЛЬКО ПОСЛЕ Base импортируем ВСЕ модели
# (порядок не важен — главное после Base!)
from app.models.user import User
from app.models.indicator import Indicator
from app.models.url_analysis import URLAnalysisResult
from app.models.email_analysis import EmailAnalysisResult
from app.models.external_feeds import ExternalFeed
from app.models.system_logs import SystemLog
from app.models.notifications import Notification
from app.models.settings import SystemSetting
from app.models.analysis_sessions import AnalysisSession
from app.models.risk_rules import RiskRule
