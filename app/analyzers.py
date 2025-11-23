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


class EmailAnalyzer:
    def analyze(self, subject: str, sender: str, body: str) -> dict:

        result = {}

        suspicious_keywords = ["verify", "urgent", "account", "password", "click"]
        score = 0

        # Проверка темы
        if any(word in subject.lower() for word in suspicious_keywords):
            result["subject_flag"] = True
            score += 1
        else:
            result["subject_flag"] = False

        # Проверка отправителя
        if not ("@" in sender and "." in sender):
            result["sender_flag"] = True
            score += 1
        else:
            result["sender_flag"] = False

        # Проверка текста письма
        if any(word in body.lower() for word in suspicious_keywords):
            result["body_flag"] = True
            score += 1
        else:
            result["body_flag"] = False

        # Итоговый вердикт
        if score == 0:
            result["verdict"] = "Безопасно"
        elif score == 1:
            result["verdict"] = "Подозрительно"
        else:
            result["verdict"] = "Фишинг"

        return result
