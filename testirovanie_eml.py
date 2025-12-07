# test_email_analyzer.py
from email_analyzer.email_analyzer import EmailAnalyzer
import json

if __name__ == "__main__":
    # читаем сырое eml
    with open("sample_email.eml", "r", encoding="utf-8", errors="ignore") as f:
        eml_text = f.read()

    analyzer = EmailAnalyzer()
    res = analyzer.analyze(eml_text)

    # выводим самое важное
    output = {
        "status": res["status"],
        "risk_score": res["risk_score"],
        "from": res["headers"]["from"],
        "reply_to": res["headers"]["reply_to"],
        "subject": res["headers"]["subject"],
        "from_domain": res["headers"]["from_domain"],
        "reply_to_domain": res["headers"]["reply_to_domain"],
        "urls": res["urls"],
        "features": res["features"],
        "matched_indicators": res["matched_indicators"],
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))
