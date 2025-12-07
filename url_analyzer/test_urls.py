from analyzer import UrlAnalyzer

analyzer = UrlAnalyzer()

urls = [
    "https://evil-phishing.com",
    "https://google.com",
    "http://fake-bank.ru"
]

for url in urls:
    print("\nАнализ:", url)
    result = analyzer.analyze(url)
    print("Статус:", result["status"])
    print("Риск:", result["risk_score"])
    print("DNS разрешился:", result["dns"]["resolvable"])
    if result["matched_indicators"]:
        print("Найден в базе!")
