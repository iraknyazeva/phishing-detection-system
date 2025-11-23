from fastapi import FastAPI, HTTPException, Request, Form
from pydantic import BaseModel, HttpUrl
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from analyzers import analyze_url_basic, EmailAnalyzer

app = FastAPI(title="Phishing Warning System — API Хайдарова",
              description="Простейший API для анализа URL и email на признаки фишинга",
              version="0.1.0")

templates = Jinja2Templates(directory="app/templates")

# --- моделей запросов/ответов ---
class URLRequest(BaseModel):
    url: HttpUrl  # pydantic проверит, что это корректный URL

class URLAnalysisResponse(BaseModel):
    url: str
    hostname: str
    suspicion_score: float
    is_phishing_suspected: bool
    details: dict

class EmailRequest(BaseModel):
    subject: str | None = None
    from_addr: str | None = None
    body: str | None = None

class EmailAnalysisResponse(BaseModel):
    subject: str | None
    from_addr: str | None
    suspicion_score: float
    is_phishing_suspected: bool
    findings: list

# --- /analyze/url ---
@app.post("/analyze/url", response_model=URLAnalysisResponse, summary="Анализ URL", tags=["url"])
async def analyze_url(payload: URLRequest):
    try:
        result = analyze_url_basic(payload.url)
        # вернём компактную структуру: details — все поля кроме высшего уровня
        details = {k: v for k, v in result.items() if k not in {"url","suspicion_score","is_phishing_suspected","hostname"}}
        return {
            "url": result["url"],
            "hostname": result["hostname"],
            "suspicion_score": result["suspicion_score"],
            "is_phishing_suspected": result["is_phishing_suspected"],
            "details": details
        }
    except Exception as e:
        # общая обработка ошибок
        raise HTTPException(status_code=500, detail=f"Ошибка анализа URL: {str(e)}")

# --- /analyze/email ---
@app.post("/analyze/email", response_model=EmailAnalysisResponse, summary="Анализ email", tags=["email"])
async def analyze_email(payload: EmailRequest):
    try:
        analyzer = EmailAnalyzer(subject=payload.subject, from_addr=payload.from_addr, body=payload.body)
        result = analyzer.analyze()
        return {
            "subject": result.get("subject"),
            "from_addr": result.get("from"),
            "suspicion_score": result.get("suspicion_score"),
            "is_phishing_suspected": result.get("is_phishing_suspected"),
            "findings": result.get("findings", [])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка анализа email: {str(e)}")

# --- Веб-страница / ---
@app.get("/", response_class=HTMLResponse, summary="Проверка URL (веб-страница)")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})