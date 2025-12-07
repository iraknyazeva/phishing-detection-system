from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional, Dict, Any
import logging
from database.models import URLAnalysisResult
from database.models.email_analysis import EmailAnalysisResult

logger = logging.getLogger(__name__)

class AnalysisRepository:
    def __init__(self, db: Session):
        self.db = db
    
    def save_url_analysis(self, analysis_data: Dict[str, Any]) -> Optional[URLAnalysisResult]:
        try:
            analysis = URLAnalysisResult(**analysis_data)
            self.db.add(analysis)
            self.db.commit()
            self.db.refresh(analysis)
            return analysis
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f'Error saving URL analysis: {e}')
            return None
    
    def save_email_analysis(self, analysis_data: Dict[str, Any]) -> Optional[EmailAnalysisResult]:
        try:
            analysis = EmailAnalysisResult(**analysis_data)
            self.db.add(analysis)
            self.db.commit()
            self.db.refresh(analysis)
            return analysis
        except SQLAlchemyError as e:
            self.db.rollback()
            logger.error(f'Error saving email analysis: {e}')
            return None
    
    def get_recent_analyses(self, limit: int = 50) -> List[Any]:
        try:
            url_analyses = self.db.query(URLAnalysisResult)\
                .order_by(URLAnalysisResult.analyzed_at.desc())\
                .limit(limit)\
                .all()
            email_analyses = self.db.query(EmailAnalysisResult)\
                .order_by(EmailAnalysisResult.analyzed_at.desc())\
                .limit(limit)\
                .all()
            return url_analyses + email_analyses
        except SQLAlchemyError as e:
            logger.error(f'Error getting recent analyses: {e}')
            return []
