# url_analyzer/rules.py
import re

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def is_valid_domain_format(domain: str) -> bool:
    """
    Примитивная проверка домена по формату.
    """
    # IP-адрес тоже можно считать валидным, если надо
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return True
    return bool(DOMAIN_REGEX.match(domain))


def apply_basic_url_rules(
    scheme: str,
    domain: str,
    path: str,
    domain_valid: bool,
) -> list[str]:
    """
    Базовый набор правил анализа URL.
    Возвращает список текстовых нарушений.
    """
    violations: list[str] = []

    if scheme not in ("http", "https"):
        violations.append(f"неподдерживаемый протокол: {scheme}")

    if not domain_valid:
        violations.append("некорректный формат домена")

    if len(domain) > 80:
        violations.append("подозрительно длинный домен")

    if "-" in domain.split(".")[0] and domain.count("-") > 3:
        violations.append("слишком много дефисов в домене")

    if any(part in domain for part in ["login", "secure", "update"]):
        violations.append("подозрительные ключевые слова в домене")

    if len(path) > 150:
        violations.append("слишком длинный путь")

    return violations
