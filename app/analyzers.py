import re
from urllib.parse import urlparse

SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"
}

def is_shortener(domain: str) -> bool:
    return domain.lower() in SHORTENER_DOMAINS

def has_ip_address_netloc(parsed):
    # netloc like 192.168.0.1 or [2001:db8::1]
    host = parsed.hostname or ""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)) or ":" in host and "[" not in host

def count_suspicious_chars(url: str):
    return sum(1 for c in url if c in "@!$%*()[]{}\\<>")

def domain_has_dash(domain: str):
    return "-" in (domain or "")

def suspicious_tld(parsed):
    # очень простой пример — список можно расширять
    tld = (parsed.hostname or "").split(".")[-1]
    return tld in {"xyz", "top", "loan", "review"}

def analyze_url_basic(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    result = {
        "url": url,
        "hostname": hostname,
        "has_ip": has_ip_address_netloc(parsed),
        "uses_shortener": is_shortener(hostname),
        "length": len(url),
        "path_length": len(path),
        "query_length": len(query),
        "suspicious_chars": count_suspicious_chars(url),
        "domain_has_dash": domain_has_dash(hostname),
        "suspicious_tld": suspicious_tld(parsed),
    }
    # Простая скоринговая метрика (0..1)
    score = 0.0
    if result["has_ip"]: score += 0.3
    if result["uses_shortener"]: score += 0.25
    if result["length"] > 100: score += 0.15
    if result["suspicious_chars"] > 3: score += 0.15
    if result["domain_has_dash"]: score += 0.05
    if result["suspicious_tld"]: score += 0.1
    result["suspicion_score"] = min(1.0, score)
    result["is_phishing_suspected"] = result["suspicion_score"] >= 0.5
    return result

# Простейший EmailAnalyzer
class EmailAnalyzer:
    def __init__(self, raw_email_text: str = None, subject: str = None, from_addr: str = None, body: str = None):
        self.raw = raw_email_text
        self.subject = subject
        self.from_addr = from_addr
        self.body = body or ""
    def analyze(self) -> dict:
        # базовые эвристики
        suspicious_phrases = ["verify your account", "update your payment", "click here", "confirm your identity"]
        score = 0.0
        findings = []
        combined = " ".join(filter(None, [self.subject or "", self.body or ""])).lower()
        for phrase in suspicious_phrases:
            if phrase in combined:
                findings.append(f"contains phrase: '{phrase}'")
                score += 0.2
        # обнаружение mismatched-from (простая проверка)
        if self.from_addr and "@" in self.from_addr:
            domain = self.from_addr.split("@", 1)[1]
            if domain.endswith(".ru"):  # пример: допустим для твоего курса
                findings.append("from country-specific TLD .ru")
                score += 0.05
        result = {
            "subject": self.subject,
            "from": self.from_addr,
            "findings": findings,
            "suspicion_score": min(1.0, score),
            "is_phishing_suspected": score >= 0.5
        }
        return result