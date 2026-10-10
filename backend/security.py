"""رمز عبور (scrypt از کتابخانه استاندارد) و توکن JWT."""
import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Optional

import jwt

_N, _R, _P = 2 ** 14, 8, 1  # حدود ۱۶ مگابایت رم به‌ازای هر هش
TOKEN_DAYS = int(os.getenv("TOKEN_DAYS", "30"))


def jwt_secret() -> str:
    return os.getenv("JWT_SECRET", "")


def require_secret() -> None:
    if len(jwt_secret()) < 32:
        raise RuntimeError(
            "متغیر JWT_SECRET تنظیم نشده یا کوتاه است (حداقل ۳۲ نویسه). "
            "آن را در Variables ریل‌وی بگذار."
        )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "$".join(
        ["scrypt", str(_N), str(_R), str(_P),
         base64.b64encode(salt).decode(), base64.b64encode(dk).decode()]
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt),
            n=int(n), r=int(r), p=int(p), dklen=32,
        )
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except Exception:
        return False


_dummy_hash: Optional[str] = None


def dummy_verify(password: str) -> None:
    """برای کاربرِ ناموجود هم همان‌قدر زمان صرف می‌شود (جلوگیری از حدس نام کاربری)."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("dummy-password")
    verify_password(password, _dummy_hash)


def create_token(user_id: int) -> str:
    now = int(time.time())
    payload = {"sub": str(user_id), "iat": now, "exp": now + TOKEN_DAYS * 86400}
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")


def decode_token(token: str) -> Optional[int]:
    try:
        data = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
        return int(data["sub"])
    except Exception:
        return None
