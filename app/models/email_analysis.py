from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float
from sqlalchemy.sql import func
from app.database import Base

class EmailAnalysisResult(Base):
    __tablename__ = "email_analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    email_subject = Column(Text)
    email_from = Column(Text, index=True)
    email_to = Column(Text)
    message_id = Column(String(255))
    risk_score = Column(Float, default=0.0)
    status = Column(String(20), default="pending")
    confidence = Column(Float, default=0.0)
    headers_analysis = Column(JSON)
    authentication_results = Column(JSON)
    content_analysis = Column(JSON)
    attachment_analysis = Column(JSON)
    extracted_urls = Column(JSON)
    url_analysis_results = Column(JSON)
    matched_indicators = Column(JSON)
    analysis_duration = Column(Float)
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())
    email_size = Column(Integer)
    email_hash = Column(String(64), unique=True, index=True)
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
