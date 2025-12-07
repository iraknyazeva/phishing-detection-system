from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.sql import func
from database.database import Base

class ExternalFeed(Base):
    __tablename__ = "external_feeds"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    url = Column(Text)
    description = Column(Text)
    sync_enabled = Column(Boolean, default=True)
    sync_interval = Column(Integer, default=3600)
    last_sync = Column(DateTime)
    last_successful_sync = Column(DateTime)
    feed_type = Column(String(50))
    authentication_config = Column(JSON)
    parser_config = Column(JSON)
    indicators_count = Column(Integer, default=0)
    last_sync_status = Column(String(20))
    last_sync_error = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_onupdate=func.now())
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
