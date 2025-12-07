import socket
import ssl
from datetime import datetime
from typing import Dict, Any

import OpenSSL


def check_ssl(domain: str) -> Dict[str, Any]:
    result = {
        "valid": False,
        "expires_soon": False,
        "days_left": 0,
        "error": ""
    }

    try:
        # Устанавливаем TLS-соединение через OpenSSL
        ctx = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der_cert = ssock.getpeercert(True)

        # Парсим сертификат OpenSSL
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)

        # Проверяем срок действия
        not_after = cert.get_notAfter().decode("ascii")
        expires = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")

        now = datetime.utcnow()
        delta = expires - now
        days_left = delta.days

        result["days_left"] = max(days_left, 0)
        result["expires_soon"] = days_left < 7

        # Проверяем CN / SAN на совпадение с доменом
        valid_domain = False

        # CN
        subject = cert.get_subject()
        if domain in subject.CN:
            valid_domain = True

        # SAN
        try:
            san_list = cert.get_extension(0)
            san_data = san_list.__str__()
            if domain in san_data:
                valid_domain = True
        except Exception:
            pass

        # итог
        result["valid"] = valid_domain and days_left > 0

    except Exception as e:
        # Ошибки SSL — отдаём, но не валим систему
        result["error"] = str(e)

    return result
