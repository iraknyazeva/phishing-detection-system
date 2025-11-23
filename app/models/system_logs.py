from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from app.database import Base

class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    level = Column(String(20), index=True)
    logger = Column(String(255), index=True)
    message = Column(Text)
    module = Column(String(100))
    operation = Column(String(100))
    user_id = Column(Integer, nullable=True)
    analysis_id = Column(Integer, nullable=True)
    indicator_id = Column(Integer, nullable=True)
    request_id = Column(String(100))
    ip_address = Column(String(45))
    user_agent = Column(Text)
    extra_data = Column(JSON)
    tags = Column(JSON)
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
