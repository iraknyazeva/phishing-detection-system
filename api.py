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









from fastapi.encoders import jsonable_encoder
import uvicorn
from fastapi import (
    FastAPI, UploadFile, File, Form, Request,
    Depends, HTTPException, status
)
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from passlib.context import CryptContext

from url_analyzer.analyzer import UrlAnalyzer
from email_analyzer.email_analyzer import EmailAnalyzer

# ====== ВАЖНО: поправьте импорты под ваш проект ======
from database.database import SessionLocal
from database.models.user import User
from database.models.analysis_sessions import AnalysisSession
from database.models.url_analysis import URLAnalysisResult
from database.models.email_analysis import EmailAnalysisResult
from database.models.system_logs import SystemLog
from database.models.indicator import Indicator
from database.models.risk_rules import RiskRule
from database.models.telegram_links import TelegramLink
# ====================================================

app = FastAPI(
    title="Phishing Detection API",
    description="API для анализа URL и EML писем",
    version="1.0.0"
)

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-please")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

url_analyzer = UrlAnalyzer()
email_analyzer = EmailAnalyzer()

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Роли: в модели у вас комментарий "user, analyst, admin" :contentReference[oaicite:9]{index=9}
# Мы добавляем monitoring, но поддерживаем analyst как “старое имя”.
ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLE_MONITORING = "monitoring"
ROLE_ANALYST_LEGACY = "analyst"
VALID_ROLES = {ROLE_USER, ROLE_ADMIN, ROLE_MONITORING, ROLE_ANALYST_LEGACY}


def hash_password(p: str) -> str:
    return pwd_context.hash(p)


def verify_password(p: str, h: str) -> bool:
    return pwd_context.verify(p, h)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from fastapi.encoders import jsonable_encoder

def log_event(
    db: Session,
    *,
    level: str,
    logger: str,
    message: str,
    module: str | None = None,
    operation: str | None = None,
    user_id: int | None = None,
    analysis_id: int | None = None,
    indicator_id: int | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    extra_data: dict | None = None,
    tags: list | None = None,
):
    safe_extra = jsonable_encoder(extra_data) if extra_data is not None else None
    safe_tags = jsonable_encoder(tags) if tags is not None else None

    entry = SystemLog(
        level=level,
        logger=logger,
        message=message,
        module=module,
        operation=operation,
        user_id=user_id,
        analysis_id=analysis_id,
        indicator_id=indicator_id,
        request_id=request_id,
        ip_address=ip_address,
        user_agent=user_agent,
        extra_data=safe_extra,
        tags=safe_tags,
    )
    db.add(entry)
    db.commit()



def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=302, headers={"Location": "/login"})

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


def require_roles(*allowed: str):
    def dep(user: User = Depends(get_current_user)):
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Недостаточно прав")
        return user
    return dep


admin_required = require_roles(ROLE_ADMIN)
monitoring_required = require_roles(ROLE_MONITORING, ROLE_ADMIN)


def ensure_active_session(db: Session, request: Request, user: User) -> AnalysisSession:
    """
    У вас analysis_sessions = (user_id, counters, timestamps). :contentReference[oaicite:10]{index=10}
    Держим текущую session_id в cookie-сессии браузера.
    """
    sess_id = request.session.get("analysis_session_id")
    if sess_id:
        sess = db.query(AnalysisSession).filter(AnalysisSession.id == sess_id).first()
        if sess and sess.user_id == user.id and sess.completed_at is None:
            return sess

    sess = AnalysisSession(
        user_id=user.id,
        session_type="web",
        total_checks=0,
        risky_found=0,
        completed_at=None,
    )
    db.add(sess)
    db.commit()
    request.session["analysis_session_id"] = sess.id
    return sess


@app.get("/")
def root():
    return RedirectResponse(url="/dashboard", status_code=302)


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





##################################
from sqlalchemy import or_, and_
from sqlalchemy.inspection import inspect
from sqlalchemy.types import Integer, Float, Boolean, JSON as SAJSON, DateTime, String, Text
from starlette.responses import Response

# --------------------------
# MONITORING CONFIG
# --------------------------

MONITOR_TABLES = {
    "analysis_sessions": {
        "title": "Analysis Sessions",
        "model": AnalysisSession,
        "readonly": True,
        "date_field": "created_at",
        "list_columns": ["id", "user_id", "session_type", "total_checks", "risky_found", "created_at", "completed_at"],
        "search_fields": [],
    },
    "url_analysis": {
        "title": "URL Analysis Results",
        "model": URLAnalysisResult,
        "readonly": True,
        "date_field": "analyzed_at",
        "list_columns": ["id", "url", "domain", "status", "risk_score", "analyzed_at", "hash"],
        "search_fields": ["url", "domain", "final_url"],
    },
    "email_analysis": {
        "title": "Email Analysis Results",
        "model": EmailAnalysisResult,
        "readonly": True,
        "date_field": "analyzed_at",
        "list_columns": ["id", "email_from", "email_subject", "status", "risk_score", "analyzed_at", "email_hash"],
        "search_fields": ["email_from", "email_subject", "message_id"],
    },
    "system_logs": {
        "title": "System Logs",
        "model": SystemLog,
        "readonly": True,
        "date_field": "timestamp",
        "list_columns": ["id", "timestamp", "level", "module", "operation", "user_id", "message"],
        "search_fields": ["logger", "module", "operation", "message"],
    },
    "telegram_links": {
        "title": "Telegram Links",
        "model": TelegramLink,
        "readonly": True,
        "date_field": "created_at",
        "list_columns": ["id", "user_id", "chat_id", "is_verified", "created_at", "updated_at"],
        "search_fields": [],
    },
    "indicators": {
        "title": "Indicators",
        "model": Indicator,
        "readonly": False,
        "date_field": "created_at",
        "list_columns": ["id", "type", "value", "risk_score", "category", "source", "is_active", "is_whitelisted", "created_at"],
        "search_fields": ["type", "value", "category", "source"],
    },
    "risk_rules": {
        "title": "Risk Rules",
        "model": RiskRule,
        "readonly": False,
        "date_field": "created_at",
        "list_columns": ["id", "name", "feature", "operator", "threshold", "risk_points", "status_override", "applies_to", "is_active", "created_at"],
        "search_fields": ["name", "feature", "operator", "applies_to", "status_override"],
    },
}

FORBIDDEN_EDIT_FIELDS = {"id", "created_at", "updated_at"}


def _parse_dt(s: str | None):
    if not s:
        return None
    # ожидаем YYYY-MM-DD или YYYY-MM-DDTHH:MM
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _safe_json_loads(s: str | None):
    if not s or not s.strip():
        return None
    return json.loads(s)


def _coerce_value(col, raw: str):
    """
    Приводим строку из формы к типу колонки.
    """
    # ✅ пустые значения и "None/null" -> None
    if raw is None:
        return None
    raw = str(raw).strip()
    if raw == "" or raw.lower() in ("none", "null", "nil"):
        return None


    if raw is None:
        return None

    raw = raw.strip()

    # пустая строка -> None (для nullable)
    if raw == "":
        return None

    t = col.type

    # Boolean
    if isinstance(t, Boolean):
        # из формы придёт "on" либо "true"/"false"
        return raw.lower() in ("1", "true", "on", "yes", "да")

    # Integer
    if isinstance(t, Integer):
        return int(raw)

    # Float
    if isinstance(t, Float):
        return float(raw)

    # JSON
    if isinstance(t, SAJSON):
        return _safe_json_loads(raw)

    # DateTime
    if isinstance(t, DateTime):
        # isoformat
        return datetime.fromisoformat(raw)

    # default: string/text
    return raw


def _model_columns(model):
    return [c for c in model.__table__.columns]


def _editable_fields(model):
    cols = _model_columns(model)
    return [c for c in cols if c.name not in FORBIDDEN_EDIT_FIELDS]


# --------------------------
# MONITORING PAGES
# --------------------------

@app.get("/monitoring")
def monitoring_home(
    request: Request,
    user: User = Depends(monitoring_required),
):
    return templates.TemplateResponse(
        "monitoring/home.html",
        {"request": request, "user": user, "tables": MONITOR_TABLES}
    )


@app.get("/monitoring/{table_name}")
def monitoring_list(
    table_name: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
    q: str | None = None,
    user_id: int | None = None,
    status: str | None = None,
    level: str | None = None,
    is_verified: str | None = None,
    is_active: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    per_page: int = 20,
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg:
        raise HTTPException(404, "Unknown table")

    model = cfg["model"]
    date_field = getattr(model, cfg["date_field"], None)

    query = db.query(model)

    # --- common filters ---
    if q and cfg["search_fields"]:
        parts = []
        for f in cfg["search_fields"]:
            col = getattr(model, f, None)
            if col is not None:
                parts.append(col.ilike(f"%{q}%"))
        if parts:
            query = query.filter(or_(*parts))

    if user_id is not None and hasattr(model, "user_id"):
        query = query.filter(getattr(model, "user_id") == user_id)

    if status and hasattr(model, "status"):
        query = query.filter(getattr(model, "status") == status)

    if level and hasattr(model, "level"):
        query = query.filter(getattr(model, "level") == level)

    if is_verified is not None and hasattr(model, "is_verified"):
        if is_verified in ("true", "1", "yes"):
            query = query.filter(getattr(model, "is_verified") == True)
        elif is_verified in ("false", "0", "no"):
            query = query.filter(getattr(model, "is_verified") == False)

    if is_active is not None and hasattr(model, "is_active"):
        if is_active in ("true", "1", "yes"):
            query = query.filter(getattr(model, "is_active") == True)
        elif is_active in ("false", "0", "no"):
            query = query.filter(getattr(model, "is_active") == False)

    # date range
    df = _parse_dt(date_from)
    dt = _parse_dt(date_to)
    if date_field is not None:
        if df:
            query = query.filter(date_field >= df)
        if dt:
            query = query.filter(date_field <= dt)

    total = query.count()

    # ordering: newest first if possible
    if date_field is not None:
        query = query.order_by(date_field.desc())
    else:
        query = query.order_by(getattr(model, "id").desc())

    # pagination
    if page < 1:
        page = 1
    if per_page < 5:
        per_page = 5
    if per_page > 200:
        per_page = 200

    rows = query.offset((page - 1) * per_page).limit(per_page).all()

    return templates.TemplateResponse(
        "monitoring/list.html",
        {
            "request": request,
            "user": user,
            "tables": MONITOR_TABLES,  # 🔴 ВАЖНО
            "cfg": cfg,
            "table_name": table_name,
            "rows": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "q": q or "",
            "filters": {
                "user_id": user_id,
                "status": status,
                "level": level,
                "is_verified": is_verified,
                "is_active": is_active,
                "date_from": date_from or "",
                "date_to": date_to or "",
            },
        }
    )


@app.get("/monitoring/{table_name}/{item_id:int}")
def monitoring_detail(
    table_name: str,
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg:
        raise HTTPException(404, "Unknown table")

    model = cfg["model"]
    row = db.query(model).filter(getattr(model, "id") == item_id).first()
    if not row:
        raise HTTPException(404, "Not found")

    # выгружаем все колонки
    data = {c.name: getattr(row, c.name) for c in model.__table__.columns}
    data = jsonable_encoder(data)  # ✅ datetime -> строка, всё JSON-safe
    return templates.TemplateResponse(
        "monitoring/detail.html",
        {
            "request": request,
            "user": user,
            "tables": MONITOR_TABLES,  # 🔴 ВАЖНО
            "cfg": cfg,
            "table_name": table_name,
            "row": row,
            "data": data,
        }
    )


# --------------------------
# EDITABLE: indicators & risk_rules
# --------------------------

@app.get("/monitoring/{table_name}/create")
def monitoring_create_page(
    table_name: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg or cfg["readonly"]:
        raise HTTPException(404, "Not editable")

    model = cfg["model"]
    fields = _editable_fields(model)

    return templates.TemplateResponse(
        "monitoring/edit.html",
        {
            "request": request,
            "user": user,
            "tables": MONITOR_TABLES,  # 🔴 ВАЖНО
            "cfg": cfg,
            "table_name": table_name,
            "mode": "create",
            "item_id": None,
            "fields": fields,
            "values": {},
            "error": None,
        }
    )

@app.post("/monitoring/{table_name}/create")
async def monitoring_create_submit(
    table_name: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg or cfg["readonly"]:
        raise HTTPException(404, "Not editable")

    model = cfg["model"]
    fields = _editable_fields(model)

    form = await request.form()
    form = dict(form)

    obj = model()
    before = None

    try:
        for col in fields:
            if col.name in form:
                setattr(obj, col.name, _coerce_value(col, str(form[col.name])))
        # если у RiskRule есть created_by — выставим текущего пользователя, если поле существует
        if hasattr(obj, "created_by") and getattr(obj, "created_by", None) is None:
            setattr(obj, "created_by", user.id)

        db.add(obj)
        db.commit()

        log_event(
            db,
            level="info",
            logger="monitoring",
            message=f"Created {table_name} id={obj.id}",
            module="monitoring",
            operation=f"create_{table_name}",
            user_id=user.id,
            extra_data={"after": {c.name: getattr(obj, c.name) for c in model.__table__.columns}},
            tags=["monitoring", table_name, "create"],
        )

        return RedirectResponse(url=f"/monitoring/{table_name}/{obj.id}", status_code=302)
    except Exception as e:
        db.rollback()
        values = {c.name: form.get(c.name, getattr(obj, c.name)) for c in fields}
        return templates.TemplateResponse(
            "monitoring/edit.html",
            {
                "request": request,
                "user": user,
                "tables": MONITOR_TABLES,  # ✅ ДОБАВИТЬ
                "cfg": cfg,
                "table_name": table_name,
                "mode": "edit",
                "item_id": None,
                "fields": fields,
                "values": values,
                "error": str(e),
            },
            status_code=400,
        )


@app.get("/monitoring/{table_name}/{item_id:int}/edit")
def monitoring_edit_page(
    table_name: str,
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg or cfg["readonly"]:
        raise HTTPException(404, "Not editable")

    model = cfg["model"]
    obj = db.query(model).filter(getattr(model, "id") == item_id).first()
    if not obj:
        raise HTTPException(404, "Not found")

    fields = _editable_fields(model)
    values = {c.name: getattr(obj, c.name) for c in fields}

    return templates.TemplateResponse(
        "monitoring/edit.html",
        {
            "request": request,
            "user": user,
            "tables": MONITOR_TABLES,  # 🔴 ВАЖНО
            "cfg": cfg,
            "table_name": table_name,
            "mode": "edit",
            "item_id": item_id,
            "fields": fields,
            "values": values,
            "error": None,
        }
    )


from fastapi.responses import RedirectResponse
from starlette.status import HTTP_302_FOUND

@app.post("/monitoring/{table_name}/{item_id:int}/edit")
async def monitoring_edit_submit(
    table_name: str,
    item_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(monitoring_required),
):
    cfg = MONITOR_TABLES.get(table_name)
    if not cfg or cfg["readonly"]:
        raise HTTPException(404, "Not editable")

    model = cfg["model"]
    obj = db.query(model).filter(getattr(model, "id") == item_id).first()
    if not obj:
        raise HTTPException(404, "Not found")

    fields = _editable_fields(model)

    # ✅ ВАЖНО: form — async
    form = await request.form()
    form = dict(form)

    before = {c.name: getattr(obj, c.name) for c in model.__table__.columns}

    try:
        for col in fields:
            if col.name in form:
                setattr(obj, col.name, _coerce_value(col, str(form[col.name])))

        db.add(obj)
        db.commit()

        after = {c.name: getattr(obj, c.name) for c in model.__table__.columns}
        try:
            log_event(
                db,
                level="info",
                logger="monitoring",
                message=f"Updated {table_name} id={obj.id}",
                module="monitoring",
                operation=f"update_{table_name}",
                user_id=user.id,
                extra_data={"before": before, "after": after},
                tags=["monitoring", table_name, "update"],
            )
        except Exception as e:
            print("log_event failed:", e)

        return RedirectResponse(url=f"/monitoring/{table_name}/{obj.id}", status_code=HTTP_302_FOUND)

    except Exception as e:
        db.rollback()
        values = {c.name: form.get(c.name, getattr(obj, c.name)) for c in fields}
        return templates.TemplateResponse(
            "monitoring/edit.html",
            {
                "request": request,
                "user": user,
                "tables": MONITOR_TABLES,  # ✅ добавь
                "cfg": cfg,
                "table_name": table_name,
                "mode": "edit",
                "item_id": item_id,
                "fields": fields,
                "values": values,
                "error": str(e),
            },
            status_code=400,
        )


###############################







@app.get("/check/url")
def check_url_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("check_url.html", {"request": request, "user": user})

@app.get("/check/email")
def check_email_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("check_email.html", {"request": request, "user": user})

# ---------- ANALYZE URL ----------
@app.post("/analyze/url")
def analyze_url(
    request: Request,
    url: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sess = ensure_active_session(db, request, user)
    start = time.time()

    result = url_analyzer.analyze(url)

    # сохраняем в url_analysis_results :contentReference[oaicite:12]{index=12}
    normalized = result.get("normalized_url") or url
    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    row = URLAnalysisResult(
        url=url,
        normalized_url=result.get("normalized_url"),
        scheme=result.get("scheme"),
        domain=result.get("domain"),
        path=result.get("path"),
        query_params=result.get("query_params"),
        risk_score=float(result.get("risk_score", 0.0)),
        status=str(result.get("status", "pending")),
        confidence=float(result.get("confidence", 0.0)),
        domain_analysis=result.get("dns") or result.get("domain_analysis"),
        ssl_analysis=result.get("ssl") or result.get("ssl_analysis"),
        reputation_analysis=result.get("reputation_analysis"),
        content_analysis=result.get("content_analysis"),
        matched_indicators=result.get("indicators") or result.get("matched_indicators"),
        redirect_chain=result.get("redirect_chain"),
        final_url=result.get("final_url"),
        analysis_duration=float(result.get("analysis_duration", time.time() - start)),
        hash=h,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(URLAnalysisResult).filter(URLAnalysisResult.hash == h).first()
        if existing:
            row = existing
        else:
            raise

    # обновляем counters в analysis_sessions :contentReference[oaicite:13]{index=13}
    sess.total_checks += 1
    if row.status in ("suspicious", "malicious", "dangerous"):
        sess.risky_found += 1
    db.commit()

    # лог в system_logs :contentReference[oaicite:14]{index=14}
    log_event(
        db,
        level="info",
        logger="web",
        message=f"URL analyzed: {url} -> {row.status} ({row.risk_score})",
        module="url",
        operation="analyze",
        user_id=user.id,
        analysis_id=row.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        extra_data={"url": url, "status": row.status, "risk_score": row.risk_score},
        tags=["url", "analysis"],
    )

    return JSONResponse(jsonable_encoder(row.to_dict()))

@app.post("/analyze/url/batch")
async def analyze_url_batch(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sess = ensure_active_session(db, request, user)

    text = (await file.read()).decode("utf-8", errors="ignore")

    urls = [
        line.strip()
        for line in text.replace("\r", "\n").split("\n")
        if line.strip()
    ]

    if not urls:
        raise HTTPException(400, "Файл пуст")

    if len(urls) > 500:
        raise HTTPException(400, "Максимум 500 URL")

    results = []
    ok = 0

    for url in urls:
        try:
            start = time.time()
            result = url_analyzer.analyze(url)

            h = hashlib.sha256(
                (result.get("normalized_url") or url).encode("utf-8")
            ).hexdigest()

            row = URLAnalysisResult(
                url=url,
                normalized_url=result.get("normalized_url"),
                scheme=result.get("scheme"),
                domain=result.get("domain"),
                path=result.get("path"),
                query_params=result.get("query_params"),
                risk_score=float(result.get("risk_score", 0.0)),
                status=str(result.get("status", "pending")),
                confidence=float(result.get("confidence", 0.0)),
                domain_analysis=result.get("dns") or result.get("domain_analysis"),
                ssl_analysis=result.get("ssl") or result.get("ssl_analysis"),
                reputation_analysis=result.get("reputation_analysis"),
                content_analysis=result.get("content_analysis"),
                matched_indicators=result.get("indicators") or result.get("matched_indicators"),
                redirect_chain=result.get("redirect_chain"),
                final_url=result.get("final_url"),
                analysis_duration=float(result.get("analysis_duration", time.time() - start)),
                hash=h,
            )

            db.add(row)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                row = db.query(URLAnalysisResult).filter(URLAnalysisResult.hash == h).first()

            sess.total_checks += 1
            if row.status in ("suspicious", "malicious", "dangerous"):
                sess.risky_found += 1
            db.commit()

            ok += 1
            results.append(jsonable_encoder(row.to_dict()))

        except Exception as e:
            db.rollback()
            results.append({
                "url": url,
                "error": str(e),
            })

    log_event(
        db,
        level="info",
        logger="web",
        message=f"Batch URL analyze: total={len(urls)} ok={ok}",
        module="url",
        operation="analyze_batch",
        user_id=user.id,
        extra_data={"total": len(urls), "ok": ok},
        tags=["url", "batch"],
    )

    return {
        "total": len(urls),
        "ok": ok,
        "failed": len(urls) - ok,
        "results": results,
    }





# ---------- ANALYZE EMAIL ----------
@app.post("/analyze/email")
async def analyze_email(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sess = ensure_active_session(db, request, user)
    start = time.time()

    content = (await file.read()).decode("utf-8", errors="ignore")
    result = email_analyzer.analyze(content)

    # сохраняем в email_analysis_results :contentReference[oaicite:15]{index=15}
    # email_hash обязателен и уникален в модели :contentReference[oaicite:16]{index=16}
    email_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()

    row = EmailAnalysisResult(
        email_subject=result.get("subject"),
        email_from=result.get("from"),
        email_to=result.get("to"),
        message_id=result.get("message_id"),
        risk_score=float(result.get("risk_score", 0.0)),
        status=str(result.get("status", "pending")),
        confidence=float(result.get("confidence", 0.0)),
        headers_analysis=result.get("headers_analysis"),
        authentication_results=result.get("authentication_results"),
        content_analysis=result.get("content_analysis"),
        attachment_analysis=result.get("attachment_analysis"),
        extracted_urls=result.get("extracted_urls"),
        url_analysis_results=result.get("url_analysis_results"),
        matched_indicators=result.get("matched_indicators"),
        analysis_duration=float(result.get("analysis_duration", time.time() - start)),
        email_size=len(content),
        email_hash=email_hash,
    )

    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        # если такое письмо уже было — просто перезапросим и вернём существующее
        db.rollback()
        existing = db.query(EmailAnalysisResult).filter(EmailAnalysisResult.email_hash == email_hash).first()
        if existing:
            row = existing
        else:
            raise

    # counters
    sess.total_checks += 1
    if row.status in ("suspicious", "malicious", "dangerous"):
        sess.risky_found += 1
    db.commit()

    log_event(
        db,
        level="info",
        logger="web",
        message=f"Email analyzed: {file.filename} -> {row.status} ({row.risk_score})",
        module="email",
        operation="analyze",
        user_id=user.id,
        analysis_id=row.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        extra_data={"filename": file.filename, "status": row.status, "risk_score": row.risk_score},
        tags=["email", "analysis"],
    )

    return JSONResponse(jsonable_encoder(row.to_dict()))


# ---------- ADMIN: USERS ----------
@app.get("/admin/users")
def admin_users(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required),
):
    users = db.query(User).order_by(User.id.asc()).all()
    roles_for_ui = [ROLE_USER, ROLE_MONITORING, ROLE_ADMIN]  # показываем “monitoring”
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "user": admin, "users": users, "roles": roles_for_ui}
    )


@app.get("/admin/users/create")
def admin_users_create_page(
    request: Request,
    admin: User = Depends(admin_required),
):
    roles_for_ui = [ROLE_USER, ROLE_MONITORING, ROLE_ADMIN]
    return templates.TemplateResponse(
        "admin_user_create.html",
        {"request": request, "user": admin, "roles": roles_for_ui}
    )


@app.post("/admin/users/create")
def admin_users_create(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required),
):
    if role not in (ROLE_USER, ROLE_MONITORING, ROLE_ADMIN):
        return templates.TemplateResponse(
            "admin_user_create.html",
            {"request": request, "user": admin, "roles": [ROLE_USER, ROLE_MONITORING, ROLE_ADMIN], "error": "Некорректная роль"},
            status_code=400
        )

    # сохраняем в users :contentReference[oaicite:17]{index=17}
    new_user = User(
        username=username.strip(),
        email=email.strip(),
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(new_user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(
            "admin_user_create.html",
            {"request": request, "user": admin, "roles": [ROLE_USER, ROLE_MONITORING, ROLE_ADMIN], "error": "Логин или email уже существует"},
            status_code=400
        )

    return RedirectResponse(url="/admin/users", status_code=302)


@app.post("/admin/users/{user_id}/toggle")
def admin_users_toggle_active(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required),
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="Нельзя отключить самого себя")

    target.is_active = not target.is_active
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=302)


@app.post("/admin/users/{user_id}/role")
def admin_users_change_role(
    user_id: int,
    role: str = Form(...),
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required),
):
    if role not in (ROLE_USER, ROLE_MONITORING, ROLE_ADMIN):
        raise HTTPException(status_code=400, detail="Некорректная роль")

    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin.id and role != ROLE_ADMIN:
        raise HTTPException(status_code=400, detail="Нельзя снять admin с самого себя")

    target.role = role
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=302)


def send_email_report(to_email: str, subject: str, html_body: str, json_data: dict, filename_prefix: str):
    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    # HTML часть
    msg.attach(MIMEText(html_body, "html"))

    # JSON вложение
    json_bytes = json.dumps(
        jsonable_encoder(json_data),
        ensure_ascii=False,
        indent=2
    ).encode("utf-8")

    attachment = MIMEApplication(json_bytes, _subtype="json")
    attachment.add_header(
        "Content-Disposition",
        "attachment",
        filename=f"{filename_prefix}_result.json"
    )
    msg.attach(attachment)

    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

def build_report_email(kind: str, data: dict) -> str:
    if kind == "url_batch":
        return f"""
        <div style="font-family:system-ui,Segoe UI,sans-serif;background:#0f172a;padding:24px">
          <div style="max-width:640px;margin:auto;background:#020617;border-radius:16px;
                      padding:24px;border:1px solid #1e293b;color:#e5e7eb">
            <h2 style="margin-top:0">📦 Пакетная проверка URL</h2>
            <p>Всего: <b>{data.get("total","—")}</b>,
               успешно: <b>{data.get("ok","—")}</b>,
               ошибок: <b>{data.get("failed","—")}</b></p>
            <p style="font-size:13px;color:#94a3b8">📎 Полный отчёт приложен JSON.</p>
          </div>
        </div>
        """
    # дальше твой старый код для url/email...
    status = data.get("status", "unknown")
    risk = data.get("risk_score", "?")

    status_map = {
        "clean": ("🟢 Безопасно", "#16a34a"),
        "suspicious": ("🟡 Подозрительно", "#eab308"),
        "malicious": ("🔴 Опасно", "#dc2626"),
        "dangerous": ("🔴 Опасно", "#dc2626"),
    }

    label, color = status_map.get(status, ("⚪ Неизвестно", "#64748b"))

    main_value = data.get("url") or data.get("email_subject") or "—"

    return f"""
    <div style="font-family:system-ui,Segoe UI,sans-serif;background:#0f172a;padding:24px">
      <div style="max-width:640px;margin:auto;background:#020617;border-radius:16px;
                  padding:24px;border:1px solid #1e293b;color:#e5e7eb">

        <h2 style="margin-top:0">📊 Отчёт проверки ({kind.upper()})</h2>

        <div style="margin:16px 0;padding:14px;border-radius:12px;
                    border:1px solid {color};background:rgba(0,0,0,.3)">
          <div style="font-size:18px;font-weight:600;color:{color}">
            {label}
          </div>
          <div style="margin-top:6px;font-size:14px">
            Риск-оценка: <b>{risk}</b>
          </div>
        </div>

        <div style="font-size:14px;line-height:1.6">
          <p><b>Объект проверки:</b><br>{main_value}</p>
          <p>⏱️ <b>Время анализа:</b> {data.get("analysis_duration", "—")} сек</p>
          <p>🎯 <b>Confidence:</b> {data.get("confidence", "—")}</p>
        </div>

        <hr style="border:none;border-top:1px solid #1e293b;margin:20px 0">

        <p style="font-size:13px;color:#94a3b8">
          📎 Полный технический отчёт приложен к письму в формате JSON.
        </p>

        <p style="font-size:12px;color:#64748b">
          Phishing Detection System
        </p>
      </div>
    </div>
    """



@app.post("/send-report")
def send_report(
    payload: dict,
    user: User = Depends(get_current_user)
):
    email = payload.get("email")
    data = payload.get("result")
    kind = payload.get("type")  # "url" | "email"

    if not email or not data or kind not in ("url", "email", "url_batch"):
        raise HTTPException(status_code=400, detail="Некорректные данные")

    html = build_report_email(kind, data)

    send_email_report(
        to_email=email,
        subject=f"Отчёт проверки ({kind.upper()})",
        html_body=html,
        json_data=data,
        filename_prefix=kind
    )

    return {"ok": True}



#telegram

def build_report_text(kind: str, data: dict) -> str:
    if kind == "url_batch":
        return "\n".join([
            "<b>📦 Пакетная проверка URL</b>",
            "",
            f"<b>Всего:</b> {data.get('total','—')}",
            f"<b>Успешно:</b> {data.get('ok','—')}",
            f"<b>Ошибок:</b> {data.get('failed','—')}",
            "",
            "📎 Полный отчёт — JSON во вложении.",
        ])
    # дальше твой старый код для url/email...
    status = str(data.get("status", "unknown"))
    risk = data.get("risk_score", "?")
    duration = data.get("analysis_duration", "—")
    confidence = data.get("confidence", "—")

    label_map = {
        "clean": "🟢 Безопасно",
        "suspicious": "🟡 Подозрительно",
        "malicious": "🔴 Опасно",
        "dangerous": "🔴 Опасно",
    }
    label = label_map.get(status, "⚪ Неизвестно")

    target = data.get("url") or data.get("email_subject") or "—"

    return "\n".join([
        f"<b>📊 Отчёт проверки ({kind.upper()})</b>",
        "",
        f"<b>Статус:</b> {label}",
        f"<b>Риск:</b> <b>{risk}</b>",
        f"<b>Время:</b> {duration} сек",
        f"<b>Confidence:</b> {confidence}",
        "",
        f"<b>Объект:</b> {target}",
        "",
        "📎 Полный отчёт — JSON во вложении.",
    ])

def tg_send_message(chat_id: str, text_html: str):
    r = httpx.post(
        f"{TG_API}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text_html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
        timeout=20,
    )
    r.raise_for_status()

def tg_send_json_file(chat_id: str, data_dict: dict, filename: str):
    payload = json.dumps(jsonable_encoder(data_dict), ensure_ascii=False, indent=2).encode("utf-8")
    bio = BytesIO(payload)
    bio.name = filename

    files = {"document": (filename, bio, "application/json")}
    form = {"chat_id": chat_id, "caption": "JSON отчёт"}

    r = httpx.post(f"{TG_API}/sendDocument", data=form, files=files, timeout=30)
    r.raise_for_status()

@app.get("/telegram/link")
def telegram_link_page(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id).first()
    return templates.TemplateResponse(
        "telegram_link.html",
        {"request": request, "user": user, "link": link, "tg_bot_username": TG_BOT_USERNAME}
    )

@app.post("/telegram/link/start")
def telegram_link_start(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not TG_BOT_TOKEN:
        raise HTTPException(500, "TG_BOT_TOKEN is not set")
    if not TG_BOT_USERNAME:
        raise HTTPException(500, "TG_BOT_USERNAME is not set")

    code = "TG-" + secrets.token_hex(3).upper()
    expires = datetime.utcnow() + timedelta(minutes=10)

    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id).first()
    if not link:
        link = TelegramLink(user_id=user.id)

    link.verification_code = code
    link.code_expires_at = expires
    link.is_verified = False

    db.add(link)
    db.commit()

    bot_link = f"https://t.me/{TG_BOT_USERNAME}"

    return {
        "ok": True,
        "code": code,
        "expires_at": expires.isoformat(),
        "bot_link": bot_link,
        "qr_url": "/telegram/link/qr",
    }

@app.get("/telegram/link/qr")
def telegram_link_qr(user: User = Depends(get_current_user)):
    if not TG_BOT_USERNAME:
        raise HTTPException(500, "TG_BOT_USERNAME is not set")

    url = f"https://t.me/{TG_BOT_USERNAME}"
    img = qrcode.make(url)

    buf = BytesIO()
    img.save(buf, format="PNG")
    return Response(content=buf.getvalue(), media_type="image/png")


@app.post("/telegram/link/finish")
def telegram_link_finish(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not TG_BOT_TOKEN:
        raise HTTPException(500, "TG_BOT_TOKEN is not set")

    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id).first()
    if not link or not link.verification_code:
        raise HTTPException(400, "Сначала нажмите «Получить код»")

    if link.code_expires_at and datetime.utcnow() > link.code_expires_at:
        raise HTTPException(400, "Код истёк. Получите новый код.")

    # читаем последние обновления
    r = httpx.get(f"{TG_API}/getUpdates", timeout=20)
    r.raise_for_status()
    data = r.json()

    code = link.verification_code.strip()

    # идём с конца (самые новые сообщения)
    for upd in reversed(data.get("result", [])):
        msg = upd.get("message") or {}
        text = (msg.get("text") or "").strip()
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")

        if not text or not chat_id:
            continue

        # пользователь должен ПРОСТО отправить код сообщением: "TG-XXXXXX"
        # допускаем, что код может быть в тексте (например, "мой код TG-XXXXXX")
        if code in text:
            link.chat_id = str(chat_id)
            link.is_verified = True
            link.verification_code = None
            link.code_expires_at = None

            db.add(link)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                log_event(
                    db,
                    level="warning",
                    logger="telegram",
                    message="Telegram chat_id already linked to another user",
                    module="telegram",
                    operation="link_finish",
                    user_id=user.id,
                    extra_data={"chat_id": str(chat_id)},
                    tags=["telegram", "link", "error"],
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "ok": False,
                        "detail": "Этот Telegram уже привязан к другой учётной записи"
                    }
                )


            return {"ok": True, "chat_id": str(chat_id)}

    return {
        "ok": False,
        "detail": "Код не найден. Откройте бота, нажмите Start и отправьте ему код сообщением (просто TG-XXXXXX), затем нажмите «Проверить привязку» ещё раз."
    }

@app.post("/send-report/telegram")
def send_report_telegram(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not TG_BOT_TOKEN:
        raise HTTPException(500, "TG_BOT_TOKEN is not set")

    kind = payload.get("type")   # url | email
    result = payload.get("result")

    if kind not in ("url", "email", "url_batch") or not result:
        raise HTTPException(400, "Некорректные данные")

    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id, TelegramLink.is_verified == True).first()
    if not link or not link.chat_id:
        raise HTTPException(400, "Telegram не привязан. Привяжите в личном кабинете.")

    text = build_report_text(kind, result)
    tg_send_message(link.chat_id, text)
    tg_send_json_file(link.chat_id, result, f"{kind}_result.json")

    return {"ok": True}
print("TG_BOT_TOKEN loaded:", bool(os.getenv("TG_BOT_TOKEN")))

@app.get("/telegram/status")
def telegram_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id).first()
    return {"linked": bool(link and link.is_verified and link.chat_id)}

@app.post("/telegram/unlink")
def telegram_unlink(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    link = db.query(TelegramLink).filter(TelegramLink.user_id == user.id).first()
    if not link:
        return {"ok": True}

    link.chat_id = None
    link.is_verified = False
    link.verification_code = None
    link.code_expires_at = None
    db.add(link)
    db.commit()
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1", port=80, reload=True)


