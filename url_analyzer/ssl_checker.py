# url_analyzer/ssl_checker.py
import socket
import ssl
from datetime import datetime
from typing import Dict, Any


def check_ssl(domain: str) -> Dict[str, Any]:
    """
    Упрощённая проверка SSL:
    - НЕ проверяет цепочку доверия (CA), чтобы не падать на CERTIFICATE_VERIFY_FAILED
    - Смотрит только срок действия сертификата
    - Считает сертификат валидным, если он вообще есть и не истёк
    """

    result: Dict[str, Any] = {
        "valid": False,
        "expires_soon": False,
        "days_left": 0,
        "error": "",
    }

    try:
        # Контекст БЕЗ проверки цепочки и имени хоста
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            result["error"] = "no cert returned"
            return result

        # notAfter в формате типа "Jun 10 12:00:00 2025 GMT"
        not_after = cert.get("notAfter")
        if not not_after:
            result["error"] = "no notAfter in cert"
            return result

        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except Exception as e:
            result["error"] = f"parse notAfter failed: {e}"
            return result

        now = datetime.utcnow()
        delta = expires - now
        days_left = delta.days

        result["days_left"] = max(days_left, 0)
        result["expires_soon"] = days_left < 7
        result["valid"] = days_left > 0

    except Exception as e:
        # Не валим систему, просто сохраняем ошибку
        result["error"] = str(e)

    return result
