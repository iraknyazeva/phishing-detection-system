from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Float
from sqlalchemy.sql import func
from app.database import Base

class URLAnalysisResult(Base):
    __tablename__ = "url_analysis_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False, index=True)
    normalized_url = Column(Text, index=True)
    scheme = Column(String(10))
    domain = Column(String(255), index=True)
    path = Column(Text)
    query_params = Column(JSON)
    risk_score = Column(Float, default=0.0)
    status = Column(String(20), default="pending")
    confidence = Column(Float, default=0.0)
    domain_analysis = Column(JSON)
    ssl_analysis = Column(JSON)
    reputation_analysis = Column(JSON)
    content_analysis = Column(JSON)
    matched_indicators = Column(JSON)
    redirect_chain = Column(JSON)
    final_url = Column(Text)
    analysis_duration = Column(Float)
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now())
    hash = Column(String(64), unique=True, index=True)
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
