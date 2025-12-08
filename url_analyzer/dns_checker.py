import socket
import subprocess


def check_dns(domain):
    result = {"resolvable": False, "ip": None, "ping_success": False, "error": ""}
    try:
        # преобразуем доменное имя в IP-адрес
        ip = socket.gethostbyname(domain)
        result["resolvable"] = True
        result["ip"] = ip
    except Exception as e:
        result["error"] = str(e)

    try:
        #пингуем домен одним пакетом
        subprocess.check_call(['ping', '-c', '1', domain],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result["ping_success"] = True
    except:
        pass

    return result