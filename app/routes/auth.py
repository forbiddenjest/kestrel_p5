"""Login, rate limiting and opaque session lifecycle."""
from datetime import timedelta
import hashlib, secrets
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.deps import csrf_protect
from app.models import LoginAttempt, Session as LoginSession, User, utcnow
from app.security import digest_token, hash_password, new_session, verify_password
from app.web import templates

router = APIRouter()
CSRF_COOKIE = "kestrel_csrf"

def _key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def _set_login_cookie(response, csrf: str):
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    return response

@router.get("/auth")
def login_page(request: Request, db: DBSession = Depends(get_db)):
    raw = request.cookies.get(settings.session_cookie)
    row = db.get(LoginSession, digest_token(raw)) if raw else None
    expires = row.expires_at.replace(tzinfo=utcnow().tzinfo) if row and row.expires_at.tzinfo is None else (row.expires_at if row else None)
    if row and expires and expires > utcnow() and row.user.active:
        return RedirectResponse("/administrator/overview" if row.user.role == "admin" else "/machines", status_code=303)
    csrf = secrets.token_urlsafe(32)
    response = templates.TemplateResponse(request, "auth.html", {"error": "", "email": "", "csrf_token": csrf})
    return _set_login_cookie(response, csrf)

@router.post("/auth")
def login(request: Request, email: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: DBSession = Depends(get_db)):
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    csrf_ok = bool(cookie_token) and secrets.compare_digest(cookie_token, csrf_token)
    email_clean = email.strip().lower()[:255]
    now = utcnow()
    ip_key, account_key = _key(_ip(request)), _key(email_clean)
    blocked = db.query(LoginAttempt).filter(LoginAttempt.attempted_at > now - timedelta(minutes=settings.login_lock_minutes), or_(LoginAttempt.ip_key == ip_key, LoginAttempt.account_key == account_key), LoginAttempt.blocked_until.is_not(None), LoginAttempt.blocked_until > now).first()
    user = db.query(User).filter(User.email == email_clean).first()
    locked_until = user.locked_until if user else None
    if locked_until and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=now.tzinfo)
    account_locked = bool(locked_until and locked_until > now)
    valid = bool(user and user.active and not account_locked and verify_password(user.password_hash, password))
    recent_ip = db.query(LoginAttempt).filter(LoginAttempt.ip_key == ip_key, LoginAttempt.attempted_at > now - timedelta(minutes=settings.login_lock_minutes)).count()
    recent_account = db.query(LoginAttempt).filter(LoginAttempt.account_key == account_key, LoginAttempt.attempted_at > now - timedelta(minutes=settings.login_lock_minutes)).count()
    if not csrf_ok or blocked or recent_ip >= settings.login_ip_limit or recent_account >= settings.login_account_limit or not valid:
        db.add(LoginAttempt(account_key=account_key, ip_key=ip_key, attempted_at=now, blocked_until=now + timedelta(minutes=settings.login_lock_minutes) if recent_ip + 1 >= settings.login_ip_limit or recent_account + 1 >= settings.login_account_limit else None))
        if user and not valid:
            user.failed_attempts += 1
            if user.failed_attempts >= settings.login_account_limit:
                user.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
        db.commit()
        retry_csrf = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(request, "auth.html", {"error": "Sign-in failed. Check your details or try again later.", "email": email_clean, "csrf_token": retry_csrf}, status_code=401)
        return _set_login_cookie(response, retry_csrf)
    user.failed_attempts = 0
    user.locked_until = None
    db.query(LoginSession).filter(LoginSession.user_id == user.id).delete(synchronize_session=False)
    raw, csrf, _row = new_session(db, user)
    db.query(LoginAttempt).filter(LoginAttempt.account_key == account_key).delete(synchronize_session=False)
    db.commit()
    target = "/account?password_change=1" if user.force_password_change else "/administrator/overview" if user.role == "admin" else "/machines"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(settings.session_cookie, raw, httponly=True, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.secure_cookies, samesite="strict", max_age=settings.session_hours * 3600, path="/")
    return response

@router.post("/auth/logout")
def logout(request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    row = getattr(request.state, "login_session", None)
    if row:
        db.delete(row)
        db.commit()
    response = RedirectResponse("/auth", status_code=303)
    response.delete_cookie(settings.session_cookie, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response
