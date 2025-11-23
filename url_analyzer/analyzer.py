# url_analyzer/analyzer.py
from dataclasses import dataclass
from urllib.parse import urlparse
from .rules import (
    is_valid_domain_format,
    apply_basic_url_rules,
)


@dataclass
class UrlAnalysisResult:
    raw_url: str
    scheme: str
    domain: str
    path: str
    is_domain_valid: bool
    rules_violations: list[str]
    is_ok: bool


class UrlAnalyzer:
    def parse_url(self, url: str) -> dict:
        """
        Базовый разбор URL: протокол, домен, путь....
        """
        parsed = urlparse(url)

        # Если протокол не указан – можно считать, что это http
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""

        return {
            "scheme": scheme,
            "domain": netloc.lower(),
            "path": path or "/",
        }

    def check_domain_format(self, domain: str) -> bool:
        """
        Проверка корректности домена (базовая).
        """
        return is_valid_domain_format(domain)

    def analyze(self, url: str) -> UrlAnalysisResult:
        """
        Объединяющий метод анализа.
        """
        parsed = self.parse_url(url)
        domain_valid = self.check_domain_format(parsed["domain"])
        violations = apply_basic_url_rules(
            scheme=parsed["scheme"],
            domain=parsed["domain"],
            path=parsed["path"],
            domain_valid=domain_valid,
        )

        is_ok = domain_valid and not violations

        return UrlAnalysisResult(
            raw_url=url,
            scheme=parsed["scheme"],
            domain=parsed["domain"],
            path=parsed["path"],
            is_domain_valid=domain_valid,
            rules_violations=violations,
            is_ok=is_ok,
        )
