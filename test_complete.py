#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from init_db import init_database
from database import SessionLocal
from repositories.threat_repository import ThreatRepository

def test_all_functionality():
    print('Testing COMPLETE database functionality...')
    
    # 1. Initialize database with ALL tables
    init_database()
    
    # 2. Test repository functionality
    db = SessionLocal()
    repo = ThreatRepository(db)
    
    # 3. Test all required methods
    print('Testing find_by_value...')
    indicator = repo.find_by_value('evil-phishing.com')
    assert indicator is not None
    
    print('Testing get_all...')
    indicators = repo.get_all()
    assert len(indicators) > 0
    
    print('Testing get_high_risk_indicators...')
    high_risk = repo.get_high_risk_indicators()
    assert len(high_risk) > 0
    
    print('Testing to_dict conversion...')
    indicator_dict = indicator.to_dict()
    assert isinstance(indicator_dict, dict)
    
    print('Testing helper methods...')
    assert indicator.is_high_risk() == True
    
    db.close()
    
    print('Database contains: indicators, url_analysis, email_analysis, external_feeds, system_logs, notifications, system_settings')

if __name__ == '__main__':
    test_all_functionality()
