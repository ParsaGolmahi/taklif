"""API سامانه تکلیف کلاس ۹۰۱ - دبیرستان شهید بهشتی

FastAPI + SQLite + JWT. فرانت روی GitHub Pages و این سرویس روی Railway.
"""
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import security
from database import connect, get_db, init_db

log = logging.getLogger("homework")

TZ = ZoneInfo(os.getenv("APP_TZ", "Asia/Tehran"))
KEEP_DAYS = int(os.getenv("HOMEWORK_KEEP_DAYS", "45"))   # تکلیف‌های قدیمی‌تر حذف می‌شوند
MAX_AHEAD_DAYS = 120                                      # حداکثر فاصله تاریخ تکلیف از امروز
STUDENT_DAILY_LIMIT = 30                                  # سقف ثبت تکلیف هر دانش‌آموز در ۲۴ ساعت
MAX_PERIODS = 8

ALLOWED_ORIGINS = [
    o.strip().rstrip("/")
    for o in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
RESERVED_USERNAMES = {"admin", "administrator", "root", "teacher", "moderator", "support"}
STAFF_ROLES = ("teacher", "admin")   # نقش‌هایی که مثل معلم می‌توانند تکلیف و برنامه را مدیریت کنند


def today() -> date:
    return datetime.now(TZ).date()


def now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------- راه‌اندازی
def ensure_teacher(conn: sqlite3.Connection) -> None:
    """حساب معلم از متغیرهای محیطی ساخته یا به‌روز می‌شود."""
    username = os.getenv("TEACHER_USERNAME", "").strip().lower()
    password = os.getenv("TEACHER_PASSWORD", "")
    if not username or not password:
        log.warning("TEACHER_USERNAME / TEACHER_PASSWORD تنظیم نشده؛ حساب معلم ساخته نشد.")
        return
    if not USERNAME_RE.match(username):
        log.error("TEACHER_USERNAME معتبر نیست (۳ تا ۲۰ حرف انگلیسی کوچک، عدد یا _).")
        return
    name = " ".join(os.getenv("TEACHER_NAME", "معلم کلاس").split()) or "معلم کلاس"
    email = os.getenv("TEACHER_EMAIL", "").strip().lower() or None

    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        if conn.execute("SELECT role FROM users WHERE id = ?", (row["id"],)).fetchone()["role"] == "admin":
            log.error("TEACHER_USERNAME با حساب مدیر یکی است؛ نادیده گرفته شد.")
            return
        if not security.verify_password(password, row["password_hash"]):
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (security.hash_password(password), row["id"]))
        conn.execute("UPDATE users SET role = 'teacher', name = ? WHERE id = ?", (name, row["id"]))
    else:
        if email and conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            email = None
        conn.execute(
            "INSERT INTO users (username, email, name, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, 'teacher', ?)",
            (username, email, name, security.hash_password(password), now_ms()),
        )
    conn.commit()


def ensure_admin(conn: sqlite3.Connection) -> None:
    """حساب مدیر از متغیرهای محیطی ساخته یا به‌روز می‌شود (برای عوض کردن رمز، متغیر را عوض و دوباره دیپلوی کن)."""
    username = os.getenv("ADMIN_USERNAME", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not username or not password:
        log.warning("ADMIN_USERNAME / ADMIN_PASSWORD تنظیم نشده؛ حساب مدیر ساخته نشد.")
        return
    if not USERNAME_RE.match(username):
        log.error("ADMIN_USERNAME معتبر نیست (۳ تا ۲۰ حرف انگلیسی کوچک، عدد یا _).")
        return
    if len(password) < 8:
        log.error("ADMIN_PASSWORD باید حداقل ۸ نویسه باشد؛ حساب مدیر ساخته نشد.")
        return
    name = " ".join(os.getenv("ADMIN_NAME", "مدیر سامانه").split()) or "مدیر سامانه"

    row = conn.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        if not security.verify_password(password, row["password_hash"]):
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                         (security.hash_password(password), row["id"]))
        conn.execute("UPDATE users SET role = 'admin', name = ? WHERE id = ?", (name, row["id"]))
    else:
        conn.execute(
            "INSERT INTO users (username, email, name, password_hash, role, created_at) "
            "VALUES (?, NULL, ?, ?, 'admin', ?)",
            (username, name, security.hash_password(password), now_ms()),
        )
    conn.commit()


def purge_old(conn: sqlite3.Connection) -> None:
    cutoff = (today() - timedelta(days=KEEP_DAYS)).isoformat()
    conn.execute("DELETE FROM homework WHERE date < ?", (cutoff,))
    conn.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO)
    security.require_secret()
    init_db()
    conn = connect()
    try:
        ensure_admin(conn)
        ensure_teacher(conn)
        purge_old(conn)
    finally:
        conn.close()
    yield


app = FastAPI(
    title="Class Homework API",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS") == "1" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if os.getenv("ENABLE_DOCS") == "1" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS or ["*"],   # در تولید ALLOWED_ORIGINS را حتماً تنظیم کن
    allow_credentials=False,                  # احراز هویت با هدر Authorization است، نه کوکی
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, __: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "اطلاعات ارسال‌شده معتبر نیست."})


# ---------------------------------------------------------------- محدودسازی تلاش‌ها
_hits: Dict[str, deque] = defaultdict(deque)


def _prune(key: str, window: int) -> deque:
    q = _hits[key]
    cutoff = time.time() - window
    while q and q[0] < cutoff:
        q.popleft()
    if len(_hits) > 5000:  # جلوگیری از رشد بی‌حد حافظه
        _hits.clear()
    return q


def check_limit(key: str, limit: int, window: int) -> None:
    if len(_prune(key, window)) >= limit:
        raise HTTPException(429, "تلاش‌ها زیاد بود. چند دقیقه بعد دوباره امتحان کن.")


def add_hit(key: str, window: int) -> None:
    _prune(key, window).append(time.time())


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- مدل‌ها و کمکی‌ها
class RegisterIn(BaseModel):
    name: str
    email: str
    username: str
    password: str


class LoginIn(BaseModel):
    username: str  # نام کاربری یا ایمیل
    password: str


class HomeworkIn(BaseModel):
    date: str
    subject: str
    text: str
    day: Optional[int] = None  # نادیده گرفته می‌شود؛ از روی تاریخ محاسبه می‌شود


class TeacherIn(BaseModel):
    name: str
    username: str
    password: str
    subject: str = ""


class TeacherUpdateIn(BaseModel):
    name: str
    subject: str = ""
    password: Optional[str] = None  # خالی = رمز عوض نشود


class PeriodIn(BaseModel):
    subject: str
    teacher: str = ""


def clean(value: str, lo: int, hi: int, message: str) -> str:
    value = re.sub(r"[ \t\u200c]*\n[ \t\u200c]*", "\n", value.replace("\r", "")).strip()
    if not (lo <= len(value) <= hi):
        raise HTTPException(400, message)
    return value


def one_line(value: str, lo: int, hi: int, message: str) -> str:
    return clean(" ".join(value.split()), lo, hi, message)


def user_out(row: sqlite3.Row) -> dict:
    return {"username": row["username"], "name": row["name"], "role": row["role"], "subject": row["subject"]}


def teacher_out(row: sqlite3.Row) -> dict:
    return {"username": row["username"], "name": row["name"], "subject": row["subject"],
            "createdAt": row["created_at"]}


def clean_subject(value: str) -> str:
    value = " ".join(value.split())
    if len(value) > 30:
        raise HTTPException(400, "نام درس حداکثر ۳۰ حرف باشد.")
    return value


def js_weekday(d: date) -> int:
    """مثل Date.getDay() در جاوااسکریپت: یکشنبه=۰ ... شنبه=۶"""
    return (d.weekday() + 1) % 7


HW_SELECT = (
    "SELECT h.id, h.date, h.subject, h.text, h.created_at, "
    "u.username, u.name, u.role, u.subject AS author_subject "
    "FROM homework h JOIN users u ON u.id = h.author_id"
)


def hw_out(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "day": js_weekday(date.fromisoformat(r["date"])),
        "date": r["date"],
        "subject": r["subject"],
        "text": r["text"],
        "author": r["name"],
        "authorRole": r["role"],
        "authorSubject": r["author_subject"],
        "authorId": r["username"],
        "createdAt": r["created_at"],
    }


def etag_json(request: Request, payload) -> Response:
    """پاسخ JSON با ETag؛ اگر چیزی عوض نشده باشد ۳۰۴ می‌دهد تا ترافیک کم شود."""
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    tag = '"' + hashlib.sha1(body).hexdigest()[:24] + '"'
    headers = {"ETag": tag, "Cache-Control": "no-cache"}
    if request.headers.get("if-none-match") == tag:
        return Response(status_code=304, headers=headers)
    return Response(body, media_type="application/json", headers=headers)


bearer = HTTPBearer(auto_error=False)


def current_user(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: sqlite3.Connection = Depends(get_db),
) -> sqlite3.Row:
    if cred is None:
        raise HTTPException(401, "اول وارد شو.")
    uid = security.decode_token(cred.credentials)
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    if row is None:
        raise HTTPException(401, "نشست معتبر نیست. دوباره وارد شو.")
    return row


def teacher_only(user: sqlite3.Row = Depends(current_user)) -> sqlite3.Row:
    if user["role"] not in STAFF_ROLES:
        raise HTTPException(403, "فقط معلم می‌تواند این کار را انجام دهد.")
    return user


def admin_only(user: sqlite3.Row = Depends(current_user)) -> sqlite3.Row:
    if user["role"] != "admin":
        raise HTTPException(403, "فقط مدیر می‌تواند این کار را انجام دهد.")
    return user


def parse_date(value: str, allow_past_equal: Optional[str] = None) -> str:
    try:
        d = date.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        raise HTTPException(400, "تاریخ معتبر نیست.")
    t = today()
    if d < t and value.strip() != allow_past_equal:
        raise HTTPException(400, "نمی‌شود برای تاریخ گذشته تکلیف ثبت کرد.")
    if d > t + timedelta(days=MAX_AHEAD_DAYS):
        raise HTTPException(400, "این تاریخ بیش از حد دور است.")
    return d.isoformat()


# ---------------------------------------------------------------- مسیرها
@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/auth/register")
def register(body: RegisterIn, request: Request, db: sqlite3.Connection = Depends(get_db)):
    ip_key = f"reg:{client_ip(request)}"
    check_limit(ip_key, limit=10, window=3600)

    name = one_line(body.name, 3, 40, "نام و نام‌خانوادگی باید ۳ تا ۴۰ حرف باشد.")
    email = body.email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(400, "ایمیل معتبر نیست.")
    username = body.username.strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "نام کاربری ۳ تا ۲۰ حرف انگلیسی، عدد یا _ باشد.")
    if username in RESERVED_USERNAMES:
        raise HTTPException(400, "این نام کاربری مجاز نیست.")
    if not (6 <= len(body.password) <= 64):
        raise HTTPException(400, "رمز عبور باید ۶ تا ۶۴ نویسه باشد.")

    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است.")
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        raise HTTPException(409, "با این ایمیل قبلاً ثبت‌نام شده است.")

    try:
        cur = db.execute(
            "INSERT INTO users (username, email, name, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, 'student', ?)",
            (username, email, name, security.hash_password(body.password), now_ms()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری یا ایمیل قبلاً ثبت شده است.")

    add_hit(ip_key, 3600)
    row = db.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return {"token": security.create_token(row["id"]), "user": user_out(row)}


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db: sqlite3.Connection = Depends(get_db)):
    ident = body.username.strip().lower()[:254]
    ip = client_ip(request)
    ip_key, id_key = f"login-ip:{ip}", f"login:{ip}:{ident}"
    check_limit(ip_key, limit=40, window=300)
    check_limit(id_key, limit=8, window=300)

    row = db.execute("SELECT * FROM users WHERE username = ? OR email = ?", (ident, ident)).fetchone()
    ok = False
    if row:
        ok = security.verify_password(body.password[:200], row["password_hash"])
    else:
        security.dummy_verify(body.password[:200])
    if not ok:
        add_hit(ip_key, 300)
        add_hit(id_key, 300)
        raise HTTPException(401, "نام کاربری یا رمز عبور درست نیست.")

    _hits.pop(id_key, None)
    return {"token": security.create_token(row["id"]), "user": user_out(row)}


@app.get("/api/auth/me")
def me(user: sqlite3.Row = Depends(current_user)):
    return {"user": user_out(user)}


@app.get("/api/schedule")
def get_schedule(request: Request, db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("SELECT day, periods FROM schedule ORDER BY day").fetchall()
    return etag_json(request, {str(r["day"]): json.loads(r["periods"]) for r in rows})


@app.put("/api/schedule")
def put_schedule(
    body: Dict[str, List[PeriodIn]],
    _: sqlite3.Row = Depends(teacher_only),
    db: sqlite3.Connection = Depends(get_db),
):
    result: Dict[str, list] = {}
    for key, periods in body.items():
        if not key.isdigit() or not (0 <= int(key) <= 6):
            raise HTTPException(400, "روز هفته معتبر نیست.")
        if len(periods) > MAX_PERIODS:
            raise HTTPException(400, f"هر روز حداکثر {MAX_PERIODS} زنگ دارد.")
        cleaned = []
        for p in periods:
            subject = " ".join(p.subject.split())
            teacher = " ".join(p.teacher.split())
            if not subject:
                continue
            if len(subject) > 30 or len(teacher) > 30:
                raise HTTPException(400, "نام درس و دبیر حداکثر ۳۰ حرف باشد.")
            cleaned.append({"subject": subject, "teacher": teacher})
        if cleaned:
            result[str(int(key))] = cleaned

    db.execute("DELETE FROM schedule")
    db.executemany(
        "INSERT INTO schedule (day, periods) VALUES (?, ?)",
        [(int(k), json.dumps(v, ensure_ascii=False)) for k, v in result.items()],
    )
    db.commit()
    return result


@app.get("/api/homework")
def list_homework(request: Request, db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(HW_SELECT + " ORDER BY h.date, h.created_at").fetchall()
    return etag_json(request, [hw_out(r) for r in rows])


@app.post("/api/homework", status_code=201)
def add_homework(
    body: HomeworkIn,
    user: sqlite3.Row = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    d = parse_date(body.date)
    subject = one_line(body.subject, 1, 30, "نام درس باید ۱ تا ۳۰ حرف باشد.")
    text = clean(body.text, 1, 600, "توضیح تکلیف باید ۱ تا ۶۰۰ حرف باشد.")

    if user["role"] not in STAFF_ROLES:
        since = now_ms() - 86_400_000
        n = db.execute(
            "SELECT COUNT(*) FROM homework WHERE author_id = ? AND created_at > ?", (user["id"], since)
        ).fetchone()[0]
        if n >= STUDENT_DAILY_LIMIT:
            raise HTTPException(429, "امروز بیش از حد تکلیف ثبت کرده‌ای. فردا دوباره امتحان کن.")

    hid = uuid.uuid4().hex
    db.execute(
        "INSERT INTO homework (id, date, subject, text, author_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (hid, d, subject, text, user["id"], now_ms()),
    )
    purge_old(db)
    row = db.execute(HW_SELECT + " WHERE h.id = ?", (hid,)).fetchone()
    return hw_out(row)


def _own_or_teacher(db: sqlite3.Connection, hid: str, user: sqlite3.Row) -> sqlite3.Row:
    row = db.execute("SELECT id, date, author_id FROM homework WHERE id = ?", (hid,)).fetchone()
    if row is None:
        raise HTTPException(404, "این تکلیف پیدا نشد.")
    if user["role"] not in STAFF_ROLES and row["author_id"] != user["id"]:
        raise HTTPException(403, "فقط ثبت‌کننده یا معلم می‌تواند این تکلیف را تغییر دهد.")
    return row


@app.put("/api/homework/{hid}")
def update_homework(
    hid: str,
    body: HomeworkIn,
    user: sqlite3.Row = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    existing = _own_or_teacher(db, hid, user)
    d = parse_date(body.date, allow_past_equal=existing["date"])
    subject = one_line(body.subject, 1, 30, "نام درس باید ۱ تا ۳۰ حرف باشد.")
    text = clean(body.text, 1, 600, "توضیح تکلیف باید ۱ تا ۶۰۰ حرف باشد.")
    db.execute("UPDATE homework SET date = ?, subject = ?, text = ? WHERE id = ?", (d, subject, text, hid))
    db.commit()
    return hw_out(db.execute(HW_SELECT + " WHERE h.id = ?", (hid,)).fetchone())


@app.delete("/api/homework/{hid}", status_code=204)
def delete_homework(
    hid: str,
    user: sqlite3.Row = Depends(current_user),
    db: sqlite3.Connection = Depends(get_db),
):
    _own_or_teacher(db, hid, user)
    db.execute("DELETE FROM homework WHERE id = ?", (hid,))
    db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------- مدیریت معلم‌ها (فقط مدیر)
@app.get("/api/admin/teachers")
def list_teachers(_: sqlite3.Row = Depends(admin_only), db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        "SELECT username, name, subject, created_at FROM users WHERE role = 'teacher' ORDER BY created_at, id"
    ).fetchall()
    return JSONResponse([teacher_out(r) for r in rows], headers={"Cache-Control": "no-store"})


@app.post("/api/admin/teachers", status_code=201)
def create_teacher(
    body: TeacherIn,
    _: sqlite3.Row = Depends(admin_only),
    db: sqlite3.Connection = Depends(get_db),
):
    name = one_line(body.name, 3, 40, "نام و نام‌خانوادگی باید ۳ تا ۴۰ حرف باشد.")
    subject = clean_subject(body.subject)
    username = body.username.strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "نام کاربری ۳ تا ۲۰ حرف انگلیسی، عدد یا _ باشد.")
    if username in RESERVED_USERNAMES:
        raise HTTPException(400, "این نام کاربری مجاز نیست.")
    if not (8 <= len(body.password) <= 64):
        raise HTTPException(400, "رمز عبور معلم باید ۸ تا ۶۴ نویسه باشد.")
    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است.")
    try:
        db.execute(
            "INSERT INTO users (username, email, name, password_hash, role, created_at, subject) "
            "VALUES (?, NULL, ?, ?, 'teacher', ?, ?)",
            (username, name, security.hash_password(body.password), now_ms(), subject),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است.")
    row = db.execute("SELECT username, name, subject, created_at FROM users WHERE username = ?", (username,)).fetchone()
    return teacher_out(row)


def _teacher_row(db: sqlite3.Connection, username: str) -> sqlite3.Row:
    row = db.execute(
        "SELECT id, username, name, subject, created_at FROM users WHERE username = ? AND role = 'teacher'",
        (username.strip().lower(),),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "این معلم پیدا نشد.")
    return row


@app.put("/api/admin/teachers/{username}")
def update_teacher(
    username: str,
    body: TeacherUpdateIn,
    _: sqlite3.Row = Depends(admin_only),
    db: sqlite3.Connection = Depends(get_db),
):
    row = _teacher_row(db, username)
    name = one_line(body.name, 3, 40, "نام و نام‌خانوادگی باید ۳ تا ۴۰ حرف باشد.")
    subject = clean_subject(body.subject)
    if body.password and not (8 <= len(body.password) <= 64):
        raise HTTPException(400, "رمز عبور معلم باید ۸ تا ۶۴ نویسه باشد.")
    db.execute("UPDATE users SET name = ?, subject = ? WHERE id = ?", (name, subject, row["id"]))
    if body.password:
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                   (security.hash_password(body.password), row["id"]))
    db.commit()
    return teacher_out(_teacher_row(db, username))


@app.delete("/api/admin/teachers/{username}", status_code=204)
def delete_teacher(
    username: str,
    _: sqlite3.Row = Depends(admin_only),
    db: sqlite3.Connection = Depends(get_db),
):
    row = _teacher_row(db, username)
    db.execute("DELETE FROM users WHERE id = ?", (row["id"],))  # تکلیف‌های او هم (CASCADE) حذف می‌شود
    db.commit()
    return Response(status_code=204)
