import ssl
import socket
import datetime


def check_ssl(domain, port=443, timeout=5):
    result = {"valid": False, "expires_soon": False, "days_left": 0, "error": ""}
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.now()).days
                result["days_left"] = days_left
                if days_left < 30:
                    result["expires_soon"] = True
    except Exception as e:
        result["error"] = str(e)

    return result