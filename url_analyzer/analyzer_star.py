import json
import sqlite3
import urllib.parse
from .dns_checker import check_dns
from .ssl_checker import check_ssl
from .whois_checker import check_whois

DB_PATH = 'phishing.db'


class UrlAnalyzer:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row

    def analyze(self, url):
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc

        # 1. DNS
        dns = check_dns(domain)

        # 2. SSL
        ssl_info = {}
        if parsed.scheme == 'https':
            ssl_info = check_ssl(domain)

        # 3. WHOIS
        whois_info = check_whois(domain)

        # 4. Поиск в базе индикаторов
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM indicators WHERE type='domain' AND value=?", (domain,))
        db_match = cur.fetchone()

        risk_score = 0.0
        status = "clean"
        matched = []

        if db_match:
            risk_score += db_match['risk_score']
            matched.append(dict(db_match))

        # Простые правила
        if not dns['resolvable']:
            risk_score += 6
        if ssl_info and not ssl_info['valid']:
            risk_score += 5
        if whois_info['age_days'] and whois_info['age_days'] < 60:
            risk_score += 4

        if risk_score >= 7:
            status = "malicious"
        elif risk_score >= 3:
            status = "suspicious"

        result = {
            "url": url,
            "domain": domain,
            "risk_score": round(risk_score, 1),
            "status": status,
            "dns": dns,
            "ssl": ssl_info,
            "whois": whois_info,
            "matched_indicators": matched
        }

        return result