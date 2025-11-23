# url_analyzer/test_urls.py
from .analyzer import UrlAnalyzer


def test_good_url():
    analyzer = UrlAnalyzer()
    result = analyzer.analyze("https://example.com/path")
    assert result.is_ok
    assert result.is_domain_valid
    assert result.scheme == "https"
    assert result.domain == "example.com"


def test_bad_domain():
    analyzer = UrlAnalyzer()
    result = analyzer.analyze("http://exa_mple!!.com/test")
    assert not result.is_ok
    assert not result.is_domain_valid
    assert "некорректный формат домена" in result.rules_violations
