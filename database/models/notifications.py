from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from database.database import Base

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    recipient = Column(String(255), index=True)
    notification_type = Column(String(50), index=True)
    subject = Column(Text)
    message = Column(Text)
    priority = Column(String(20), default="medium")
    trigger_event = Column(String(100))
    related_analysis_id = Column(Integer, nullable=True)
    related_indicator_id = Column(Integer, nullable=True)
    status = Column(String(20), default="pending")
    sent_at = Column(DateTime)
    delivery_attempts = Column(Integer, default=0)
    last_attempt_error = Column(Text)
    retry_config = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_onupdate=func.now())
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
