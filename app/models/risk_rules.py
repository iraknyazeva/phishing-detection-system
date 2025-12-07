from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, func
from app.database import Base

class RiskRule(Base):
    __tablename__ = "risk_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    condition = Column(Text, nullable=False)
    risk_points = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    description = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())