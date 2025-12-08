# api.py
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from url_analyzer.analyzer import UrlAnalyzer
from email_analyzer.email_analyzer import EmailAnalyzer

# --------------------------
# Создаём приложение FastAPI
# --------------------------
app = FastAPI(
    title="Phishing Detection API",
    description="API для анализа URL и EML писем",
    version="1.0.0"
)

# --------------------------
# Подключаем шаблоны HTML
# --------------------------
# Папка templates/ должна находиться в корне проекта
templates = Jinja2Templates(directory="templates")

# (опционально) статика, если понадобится CSS/JS
app.mount("/static", StaticFiles(directory="static"), name="static")

# --------------------------
# Инициализируем анализаторы
# --------------------------
url_analyzer = UrlAnalyzer()
email_analyzer = EmailAnalyzer()


# --------------------------
# Корневой endpoint
# --------------------------
@app.get("/")
def root():
    return {"message": "Phishing Detection API is running"}


# --------------------------
# Веб-интерфейс (страница)
# --------------------------
@app.get("/web")
def web_interface(request: Request):
    """
    Отдаём HTML страницу с формами проверки URL и письма.
    """
    return templates.TemplateResponse("index.html", {"request": request})


# --------------------------
# API: анализ URL
# --------------------------
@app.post("/analyze/url")
def analyze_url(url: str = Form(...)):
    result = url_analyzer.analyze(url)
    return JSONResponse(result)


# --------------------------
# API: анализ EML
# --------------------------
@app.post("/analyze/email")
async def analyze_email(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="ignore")
    result = email_analyzer.analyze(content)
    return JSONResponse(result)


# --------------------------
# Автоматический запуск сервера
# --------------------------
if __name__ == "__main__":
    uvicorn.run(
        "api:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
