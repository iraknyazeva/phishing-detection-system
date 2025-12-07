# email_analyzer/analyzer_star.py
from dataclasses import dataclass, field
from email import message_from_string
from email.message import Message
from typing import Dict, List

from .utils import (
    decode_header_value,
    extract_links_from_text,
)


@dataclass
class EmailAnalysisResult:
    raw_email: str
    headers: Dict[str, str]
    basic_fields: Dict[str, str]
    links: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    is_ok: bool = True


class EmailAnalyzer:
    def parse_headers(self, email: str) -> Dict[str, str]:
        """
        Разбор и декодирование заголовков.
        """
        msg: Message = message_from_string(email)
        headers: Dict[str, str] = {}

        for k, v in msg.items():
            headers[k] = decode_header_value(v)

        return headers

    def extract_basic_fields(self, email: str) -> Dict[str, str]:
        """
        Выделяем From, To, Subject, Date.
        """
        msg: Message = message_from_string(email)

        def g(name: str) -> str:
            val = msg.get(name, "")
            return decode_header_value(val)

        return {
            "from": g("From"),
            "to": g("To"),
            "subject": g("Subject"),
            "date": g("Date"),
        }

    def extract_links(self, email: str) -> List[str]:
        """
        Ищем ссылки в тексте/HTML.
        """
        msg: Message = message_from_string(email)

        texts: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True) or b""
                        charset = part.get_content_charset() or "utf-8"
                        texts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        continue
        else:
            payload = msg.get_payload(decode=True) or b""
            charset = msg.get_content_charset() or "utf-8"
            texts.append(payload.decode(charset, errors="replace"))

        links: List[str] = []
        for txt in texts:
            links.extend(extract_links_from_text(txt))

        # убираем дубли
        return sorted(set(links))

    def analyze(self, email: str) -> EmailAnalysisResult:
        """
        Объединяющий метод анализа (....).
        """
        headers = self.parse_headers(email)
        fields = self.extract_basic_fields(email)
        links = self.extract_links(email)

        issues: List[str] = []

        if not fields["from"]:
            issues.append("отсутствует заголовок From")

        if not fields["subject"]:
            issues.append("пустой Subject")

        if len(links) > 20:
            issues.append("подозрительно много ссылок в письме")

        # пример примитивного правила
        suspicious_words = ["urgent", "verify", "password", "login"]
        subj_lower = fields["subject"].lower()
        if any(w in subj_lower for w in suspicious_words):
            issues.append("подозрительные слова в теме письма")

        is_ok = not issues

        return EmailAnalysisResult(
            raw_email=email,
            headers=headers,
            basic_fields=fields,
            links=links,
            issues=issues,
            is_ok=is_ok,
        )
