from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, HttpUrl
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi import status
from fastapi.templating import Jinja2Templates

from analyzers.url_analyzer import analyze_url_basic
from analyzers.email_analyzer import EmailAnalyzer


app = FastAPI(title="Phishing Warning System — API",
              description="API для анализа URL и email на признаки фишинга",
              version="0.1.0")

templates = Jinja2Templates(directory="app/templates")


# --- моделей запросов/ответов ---
class URLRequest(BaseModel):
    url: HttpUrl  

class URLAnalysisResponse(BaseModel):
    url: str
    hostname: str
    suspicion_score: float
    is_phishing_suspected: bool
    details: dict

from typing import Optional

class EmailRequest(BaseModel):
    subject: Optional[str] = None
    from_addr: Optional[str] = None
    body: Optional[str] = None


class EmailAnalysisResponse(BaseModel):
    subject: Optional[str]
    from_addr: Optional[str]
    suspicion_score: float
    is_phishing_suspected: bool
    findings: list

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
    )

# --- /analyze/url ---
@app.post("/analyze/url", response_model=URLAnalysisResponse, summary="Анализ URL", tags=["url"])
async def analyze_url(payload: URLRequest):
    try:
        result = analyze_url_basic(payload.url)
        details = {k: v for k, v in result.items() if k not in {"url","suspicion_score","is_phishing_suspected","hostname"}}
        return {
            "url": result["url"],
            "hostname": result["hostname"],
            "suspicion_score": result["suspicion_score"],
            "is_phishing_suspected": result["is_phishing_suspected"],
            "details": details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка анализа URL: {str(e)}")


@app.post("/analyze/email", response_model=EmailAnalysisResponse, summary="Анализ email", tags=["email"])
async def analyze_email(payload: EmailRequest):
    try:
        analyzer = EmailAnalyzer()
        result = analyzer.analyze(payload.subject, payload.from_addr, payload.body)

        return {
            "subject": payload.subject,
            "from_addr": payload.from_addr,
            "suspicion_score": result.get("suspicion_score"),
            "is_phishing_suspected": result.get("is_phishing_suspected"),
            "findings": result.get("findings", [])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка анализа email: {str(e)}")


# --- Веб-страница / ---
@app.get("/", summary="Форма проверки URL")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})