from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship

from database.database import Base


class TelegramLink(Base):
    __tablename__ = "telegram_links"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True, index=True)
    chat_id = Column(String(64), nullable=True, unique=True, index=True)

    is_verified = Column(Boolean, nullable=False, default=False)

    # код для привязки: TG-XXXXXX
    verification_code = Column(String(64), nullable=True, index=True)
    code_expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    user = relationship("User")
