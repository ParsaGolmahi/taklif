"""اتصال SQLite و ساخت جدول‌ها."""
import os
import sqlite3


def _db_path() -> str:
    path = os.getenv("DB_PATH")
    if path:
        return path
    # روی Railway، Volume را روی /data سوار کن تا داده‌ها بعد از هر دیپلوی بمانند.
    if os.path.isdir("/data"):
        return "/data/app.db"
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.db")


DB_PATH = _db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT UNIQUE COLLATE NOCASE,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'teacher', 'admin')),
    created_at    INTEGER NOT NULL,
    subject       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS homework (
    id         TEXT PRIMARY KEY,
    date       TEXT NOT NULL,
    subject    TEXT NOT NULL,
    text       TEXT NOT NULL,
    author_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_homework_date ON homework(date);
CREATE INDEX IF NOT EXISTS idx_homework_author ON homework(author_id, created_at);
CREATE TABLE IF NOT EXISTS schedule (
    day     INTEGER PRIMARY KEY,
    periods TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _migrate_users(conn: sqlite3.Connection) -> None:
    """دیتابیس‌های قدیمی (بدون نقش admin و ستون subject) را بدون از دست رفتن داده ارتقا می‌دهد."""
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    if not row or "'admin'" in row[0]:
        return
    # SQLite نمی‌تواند CHECK را عوض کند؛ جدول را بازسازی می‌کنیم.
    # foreign_keys باید خاموش باشد وگرنه حذف users تکلیف‌ها را هم پاک می‌کند.
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.executescript(
            """
            BEGIN;
            CREATE TABLE users_new (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email         TEXT UNIQUE COLLATE NOCASE,
                name          TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'teacher', 'admin')),
                created_at    INTEGER NOT NULL,
                subject       TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO users_new (id, username, email, name, password_hash, role, created_at)
                SELECT id, username, email, name, password_hash, role, created_at FROM users;
            DROP TABLE users;
            ALTER TABLE users_new RENAME TO users;
            COMMIT;
            """
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        _migrate_users(conn)
        conn.commit()
    finally:
        conn.close()


def get_db():
    """وابستگی FastAPI: یک اتصال به‌ازای هر درخواست."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
