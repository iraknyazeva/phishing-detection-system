# email_analyzer/test_emails.py
from .analyzer import EmailAnalyzer


SAMPLE_EMAIL = """From: Test <test@example.com>
To: User <user@example.com>
Subject: Hello world
Date: Tue, 21 Nov 2023 10:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Here is a link: https://example.com/test
"""


def test_basic_email_analysis():
    analyzer = EmailAnalyzer()
    result = analyzer.analyze(SAMPLE_EMAIL)

    assert result.is_ok
    assert result.basic_fields["from"].startswith("Test")
    assert "https://example.com/test" in result.links
