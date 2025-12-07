from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, JSON
from sqlalchemy.sql import func
from database.database import Base

class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String(50), nullable=False, index=True)
    value = Column(String(1000), nullable=False, index=True)
    risk_score = Column(Integer, default=1, nullable=False)
    description = Column(Text)
    category = Column(String(100))
    source = Column(String(100), default="manual")
    confidence = Column(Float, default=1.0)
    external_id = Column(String(255))
    external_source = Column(String(100))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    is_active = Column(Boolean, default=True)
    is_whitelisted = Column(Boolean, default=False)
    tags = Column(JSON)
    tlp_level = Column(String(10), default="green")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_onupdate=func.now())
    expires_at = Column(DateTime)
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    def is_high_risk(self):
        return self.risk_score >= 7
