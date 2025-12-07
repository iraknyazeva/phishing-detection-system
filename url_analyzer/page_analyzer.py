# url_analyzer/page_analyzer.py
from __future__ import annotations

from typing import Any, Dict

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None


def analyze_page(url: str) -> Dict[str, Any]:
    """
    Анализ содержимого HTML-страницы.
    Можно легко расширять (поиск форм, скриптов, iframe, ключевых слов и т.д.).
    """
    result: Dict[str, Any] = {
        "fetched": False,
        "status_code": None,
        "error": "",
        "title": "",
        "form_count": 0,
        "password_field_count": 0,
        "has_iframe": False,
        "suspicious_keywords": [],
        "features": {},
    }

    if requests is None or BeautifulSoup is None:
        result["error"] = "requests/bs4 not installed"
        return result

    try:
        resp = requests.get(url, timeout=5)
        result["status_code"] = resp.status_code
        if resp.status_code != 200:
            result["error"] = f"unexpected status code {resp.status_code}"
            return result
    except Exception as e:
        result["error"] = str(e)
        return result

    result["fetched"] = True
    html = resp.text
    soup = BeautifulSoup(html, "html.parser")

    title_tag = soup.find("title")
    if title_tag:
        result["title"] = title_tag.get_text(strip=True)

    forms = soup.find_all("form")
    result["form_count"] = len(forms)

    password_fields = soup.find_all("input", {"type": "password"})
    result["password_field_count"] = len(password_fields)

    iframes = soup.find_all("iframe")
    result["has_iframe"] = bool(iframes)

    # простая эвристика по тексту
    suspicious_keywords = ["verify", "login", "confirm", "update", "password"]
    text_snippet = soup.get_text(" ", strip=True).lower()[:5000]
    found_keywords = [kw for kw in suspicious_keywords if kw in text_snippet]
    result["suspicious_keywords"] = found_keywords

    features = {
        "page_form_count": result["form_count"],
        "page_password_fields": result["password_field_count"],
        "page_has_iframe": result["has_iframe"],
        "page_keyword_hits": len(found_keywords),
    }
    result["features"] = features

    return result
