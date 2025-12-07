from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional
import logging
from database.models import Indicator

logger = logging.getLogger(__name__)

class ThreatRepository:
    def __init__(self, db: Session):
        self.db = db
    
    def find_by_value(self, value: str) -> Optional[Indicator]:
        try:
            return self.db.query(Indicator).filter(Indicator.value == value).first()
        except SQLAlchemyError as e:
            logger.error(f'Error finding indicator by value: {e}')
            return None
    
    def get_all(self, active_only: bool = True) -> List[Indicator]:
        try:
            query = self.db.query(Indicator)
            if active_only:
                query = query.filter(Indicator.is_active == True)
            return query.all()
        except SQLAlchemyError as e:
            logger.error(f'Error getting indicators: {e}')
            return []
    
    def load_initial_indicators(self) -> bool:
        initial_indicators = [
            {'type': 'domain', 'value': 'evil-phishing.com', 'risk_score': 10, 'description': 'Known phishing domain', 'category': 'phishing'},
            {'type': 'domain', 'value': 'fake-bank.ru', 'risk_score': 8, 'description': 'Fake banking site', 'category': 'phishing'},
            {'type': 'keyword', 'value': 'срочно обновите пароль', 'risk_score': 5, 'description': 'Phishing wording', 'category': 'suspicious'},
            {'type': 'keyword', 'value': 'ваш аккаунт заблокирован', 'risk_score': 6, 'description': 'Phishing wording', 'category': 'suspicious'}
        ]
        try:
            for data in initial_indicators:
                if not self.find_by_value(data['value']):
                    indicator = Indicator(**data)
                    self.db.add(indicator)
            self.db.commit()
            return True
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f'Error loading initial indicators: {e}')
            return False
    
    def find_by_type(self, indicator_type: str) -> List[Indicator]:
        try:
            return self.db.query(Indicator).filter(
                Indicator.type == indicator_type,
                Indicator.is_active == True
            ).all()
        except SQLAlchemyError as e:
            logger.error(f'Error finding by type: {e}')
            return []
    
    def get_high_risk_indicators(self, threshold: int = 7) -> List[Indicator]:
        try:
            return self.db.query(Indicator).filter(
                Indicator.risk_score >= threshold,
                Indicator.is_active == True
            ).all()
        except SQLAlchemyError as e:
            logger.error(f'Error getting high risk indicators: {e}')
            return []
