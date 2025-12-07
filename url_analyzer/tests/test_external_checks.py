from ..dns_checker import check_dns
from ..ssl_checker import check_ssl
from ..whois_checker import check_whois


def test_dns_google_resolvable():
    result = check_dns("google.com")
    assert result["resolvable"] is True


def test_ssl_google_valid():
    result = check_ssl("google.com")
    assert result["valid"] is True


def test_whois_google_has_created_date():
    result = check_whois("google.com")
    print(result)
    assert result["created"] is not None
