# email_analyzer/utils.py
import re
from email.header import decode_header
from typing import List


def decode_header_value(value: str) -> str:
    """
    Обработка нетипичных форматов заголовков (RFC 2047).
    """
    if not value:
        return ""
    decoded_parts = decode_header(value)
    result = ""
    for part, enc in decoded_parts:
        if isinstance(part, bytes):
            encoding = enc or "utf-8"
            try:
                result += part.decode(encoding, errors="replace")
            except Exception:
                result += part.decode("utf-8", errors="replace")
        else:
            result += part
    return result


URL_REGEX = re.compile(
    r"(https?://[^\s<>\"]+)",
    re.IGNORECASE,
)


def extract_links_from_text(text: str) -> List[str]:
    return URL_REGEX.findall(text)
