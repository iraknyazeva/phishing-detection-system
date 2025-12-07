# email_analyzer/email_features.py
from email import message_from_string
from email.message import Message
from typing import Dict, Any, List
import re
import urllib.parse


URL_REGEX = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

SUSPICIOUS_SUBJECT_KEYWORDS = [
    "urgent", "verify", "confirm", "password", "account", "suspended",
    "подтвердите", "срочно", "безопасность", "пароль",
]

SUSPICIOUS_BODY_KEYWORDS = [
    "verify your account",
    "confirm your password",
    "login to your account",
    "подтвердите аккаунт",
    "подтвердите свою учетную запись",
    "срочно войдите",
]


def _extract_text_from_message(msg: Message) -> str:
    """
    Вынимаем текст из EML (очень простой вариант: text/plain + text/html как есть).
    """
    parts: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
                        parts.append(text)
                except Exception:
                    continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(msg.get_content_charset() or "utf-8", errors="ignore")
                parts.append(text)
        except Exception:
            pass

    return "\n".join(parts)


def _extract_urls_from_text(text: str) -> List[str]:
    return list(set(URL_REGEX.findall(text)))


def extract_email_features(eml_text: str) -> Dict[str, Any]:
    """
    На вход: сырой текст EML (str).
    На выход:
      - headers: From, To, Subject, Reply-To, Message-ID, Received-SPF, Authentication-Results
      - body_text
      - urls
      - features (фичи для RiskEngine)
    """
    msg: Message = message_from_string(eml_text)

    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    subject = msg.get("Subject", "")
    reply_to = msg.get("Reply-To", "")
    message_id = msg.get("Message-ID", "")

    received_spf = msg.get("Received-SPF", "")
    auth_results = msg.get("Authentication-Results", "")

    body_text = _extract_text_from_message(msg)
    urls = _extract_urls_from_text(body_text)

    # === Признаки ===
    features: Dict[str, Any] = {}

    # 1) базовые признаки письма
    features["email_has_reply_to"] = bool(reply_to)
    features["email_subject_length"] = len(subject)
    features["email_body_length"] = len(body_text)
    features["email_url_count"] = len(urls)

    # 2) простейшая эвристика: From и Reply-To разные → подозрительно
    features["email_from_reply_mismatch"] = False
    if from_header and reply_to and from_header.strip().lower() != reply_to.strip().lower():
        features["email_from_reply_mismatch"] = True

    # 3) подозрительные слова в теме
    subj_lower = subject.lower()
    features["email_subject_suspicious_keywords"] = sum(
        1 for kw in SUSPICIOUS_SUBJECT_KEYWORDS if kw in subj_lower
    )

    # 4) подозрительные фразы в теле
    body_lower = body_text.lower()
    features["email_body_suspicious_keywords"] = sum(
        1 for kw in SUSPICIOUS_BODY_KEYWORDS if kw in body_lower
    )

    # 5) SPF / DKIM / DMARC — парсим по строкам заголовков
    spf_fail = "fail" in received_spf.lower() if received_spf else False
    spf_pass = "pass" in received_spf.lower() if received_spf else False

    auth_lower = auth_results.lower()
    dkim_fail = "dkim=fail" in auth_lower
    dkim_pass = "dkim=pass" in auth_lower
    dmarc_fail = "dmarc=fail" in auth_lower
    dmarc_pass = "dmarc=pass" in auth_lower

    features["email_spf_pass"] = spf_pass
    features["email_spf_fail"] = spf_fail
    features["email_dkim_pass"] = dkim_pass
    features["email_dkim_fail"] = dkim_fail
    features["email_dmarc_pass"] = dmarc_pass
    features["email_dmarc_fail"] = dmarc_fail

    # Можно добавить ещё фичи по адресам (from-domain, to-domain и т.п.)
    def _extract_domain_from_addr(addr: str) -> str:
        # грубо: берём часть после @
        if "<" in addr and ">" in addr:
            inside = addr.split("<", 1)[1].split(">", 1)[0]
        else:
            inside = addr
        if "@" in inside:
            return inside.split("@", 1)[1].strip().lower()
        return ""

    from_domain = _extract_domain_from_addr(from_header)
    reply_to_domain = _extract_domain_from_addr(reply_to)

    features["email_from_domain_present"] = bool(from_domain)
    features["email_from_reply_domain_mismatch"] = (
        bool(from_domain) and bool(reply_to_domain) and from_domain != reply_to_domain
    )

    return {
        "headers": {
            "from": from_header,
            "to": to_header,
            "subject": subject,
            "reply_to": reply_to,
            "message_id": message_id,
            "received_spf": received_spf,
            "authentication_results": auth_results,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
        },
        "body_text": body_text,
        "urls": urls,
        "features": features,
    }
