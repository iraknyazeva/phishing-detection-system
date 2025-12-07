from url_analyzer.analyzer import UrlAnalyzer
import json

an = UrlAnalyzer()
res = an.analyze("https://youtube.com")
print(json.dumps(res, indent=2, ensure_ascii=False))
