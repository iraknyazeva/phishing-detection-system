from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.sql import func
from database.database import Base

class SystemSetting(Base):
    __tablename__ = "system_settings"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(255), unique=True, index=True, nullable=False)
    value = Column(Text)
    value_type = Column(String(20), default="string")
    category = Column(String(100), index=True)
    description = Column(Text)
    is_public = Column(Boolean, default=False)
    validation_rules = Column(JSON)
    allowed_values = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_onupdate=func.now())
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
