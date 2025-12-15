# api.py
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from url_analyzer.analyzer import UrlAnalyzer
from email_analyzer.email_analyzer import EmailAnalyzer

# api.py
import os
from dotenv import load_dotenv
load_dotenv()
import time
import hashlib
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from fastapi.encoders import jsonable_encoder
import json
from email.mime.application import MIMEApplication
from fastapi.encoders import jsonable_encoder
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.mail.ru")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER", "testrabotaitv@mail.ru")
SMTP_PASS = os.getenv("SMTP_PASS", "HJIzhXmJM6HIpZzgVOl3")


import qrcode
from fastapi.responses import Response

from io import BytesIO
import secrets
from datetime import timedelta
import httpx
from sqlalchemy import or_
from database.models.telegram_links import TelegramLink
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_BOT_USERNAME = os.getenv("TG_BOT_USERNAME", "")
TG_API = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"
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



# ---------- LOGIN ----------
@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Неверный логин/пароль или пользователь отключён", "username": username},
            status_code=400
        )

    request.session["user_id"] = user.id
    request.session["role"] = user.role

    # last_login есть в users :contentReference[oaicite:11]{index=11}
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    # стартуем/возобновляем сессию анализа
    ensure_active_session(db, request, user)

    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# ---------- DASHBOARD (ЛК) ----------
@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Подтягиваем текущую сессию для статистики в ЛК
    sess = ensure_active_session(db, request, user)

    # monitoring и analyst считаем как “мониторинг”
    effective_role = ROLE_MONITORING if user.role == ROLE_ANALYST_LEGACY else user.role

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "effective_role": effective_role,
            "session": sess,
        }
    )




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
