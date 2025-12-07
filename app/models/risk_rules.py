from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, func
from app.database import Base


class RiskRule(Base):
    __tablename__ = "risk_rules"

    id = Column(Integer, primary_key=True, index=True)

    # Чисто для человека – как называется правило
    name = Column(String(255), nullable=False)

    # КАКОЙ ПРИЗНАК проверяем (должен совпадать с ключом в features)
    # Например: "whois_age_days", "ssl_valid", "indicator_count"
    feature = Column(String(100), nullable=False)

    # КАК СРАВНИВАЕМ: "lt", "gt", "eq", "is_true", "is_false" и т.п.
    operator = Column(String(20), nullable=False)

    # С чем сравниваем (порог/значение) – храним как строку, потом приводим к числу/булю
    value = Column(String(50), nullable=True)

    # Сколько добавить баллов риска, если правило сработало
    risk_points = Column(Integer, nullable=False)

    # Можно ли этим правилом поднять статус ("clean" / "suspicious" / "malicious")
    status_override = Column(String(20), nullable=True)

    # Для каких объектов правило применяется: только URL, только письма или для обоих
    applies_to = Column(String(20), nullable=False, default="url")  # "url", "email", "both"

    is_active = Column(Boolean, default=True)
    description = Column(Text)

    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
