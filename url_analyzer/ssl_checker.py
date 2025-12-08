# url_analyzer/ssl_checker.py
import ssl
from datetime import datetime
from typing import Dict, Any

import OpenSSL


def check_ssl(domain: str) -> Dict[str, Any]:
    """
    Проверка SSL через ssl.get_server_certificate + pyOpenSSL.
    Что делаем:
    - запрашиваем реальный сертификат у сервера
    - парсим его через OpenSSL
    - считаем, сколько дней осталось
    - если сертификат есть и не истёк -> valid = True
    """

    result: Dict[str, Any] = {
        "valid": False,
        "expires_soon": False,
        "days_left": 0,
        "error": "",
    }

    try:
        # Получаем PEM-сертификат (без проверки цепочки доверия)
        pem_cert = ssl.get_server_certificate((domain, 443))
        if not pem_cert:
            result["error"] = "empty pem from get_server_certificate"
            return result

        # Парсим сертификат через OpenSSL
        cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            pem_cert.encode("utf-8"),
        )

        # Достаём дату окончания
        not_after = cert.get_notAfter().decode("ascii")  # формат: YYYYMMDDHHMMSSZ
        expires = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")

        now = datetime.utcnow()
        delta = expires - now
        days_left = delta.days

        result["days_left"] = max(days_left, 0)
        result["expires_soon"] = days_left < 7
        result["valid"] = days_left > 0

    except Exception as e:
        # Если что-то пошло не так — пишем ошибку, но НЕ валим программу
        result["error"] = str(e)

    return result
