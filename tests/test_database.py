import pytest
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from database.database import create_tables, SessionLocal
from database.repositories.threat_repository import ThreatRepository

class TestDatabase:
    def setup_method(self):
        create_tables()
        self.db = SessionLocal()
        self.repo = ThreatRepository(self.db)
        self.repo.load_initial_indicators()
    
    def teardown_method(self):
        self.db.close()
    
    def test_find_by_value(self):
        indicator = self.repo.find_by_value("evil-phishing.com")
        assert indicator is not None
        assert indicator.risk_score == 10
    
    def test_get_all(self):
        indicators = self.repo.get_all()
        assert len(indicators) >= 4
    
    def test_high_risk_indicators(self):
        high_risk = self.repo.get_high_risk_indicators(7)
        assert len(high_risk) >= 2
    
    def test_to_dict_conversion(self):
        indicator = self.repo.find_by_value("evil-phishing.com")
        data = indicator.to_dict()
        assert "value" in data
        assert "risk_score" in data

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
