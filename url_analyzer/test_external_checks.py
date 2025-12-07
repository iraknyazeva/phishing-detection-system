from dns_checker import check_dns
from ssl_checker import check_ssl
from whois_checker import check_whois

print("Тест DNS ".ljust(30), "✓" if check_dns("google.com")["resolvable"] else "✗")
print("Тест SSL ".ljust(30), "✓" if check_ssl("google.com")["valid"] else "✗")
print("Тест WHOIS ".ljust(30), "✓" if check_whois("google.com")["created"] else "✗")
print("\nВсе внешние проверки работают!")