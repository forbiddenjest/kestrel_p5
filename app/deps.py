"""Authentication, authorization, CSRF validation and browser security headers."""
import secrets
from datetime import timezone
from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.models import Session as LoginSession, User, Machine, utcnow
from app.security import digest_token, csrf_matches

async def require_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    raw = request.cookies.get(settings.session_cookie)
    if not raw:
        raise HTTPException(401, "Sign in required")
    row = db.get(LoginSession, digest_token(raw))
    expires = row.expires_at.replace(tzinfo=timezone.utc) if row and row.expires_at.tzinfo is None else (row.expires_at if row else None)
    if not row or expires is None or expires <= utcnow():
        if row:
            db.delete(row)
            db.commit()
        raise HTTPException(401, "Sign in required")
    if not row.user.active:
        raise HTTPException(403, "Account suspended")
    request.state.login_session = row
    csrf_cookie = request.cookies.get("kestrel_csrf", "")
    request.state.csrf_token = csrf_cookie if csrf_cookie and secrets.compare_digest(digest_token(csrf_cookie), row.csrf_hash) else ""
    if row.user.force_password_change and request.url.path not in {"/account", "/account/password", "/auth/logout"}:
        raise HTTPException(303, headers={"Location": "/account?password_change=1"})
    return row.user

def require_owner(machine_id: str):
    async def guard(request: Request, db: DBSession = Depends(get_db), user: User = Depends(require_user)) -> Machine:
        resolved_id = request.path_params.get(machine_id)
        if not isinstance(resolved_id, str):
            raise HTTPException(404, "Machine not found")
        machine = db.get(Machine, resolved_id)
        if not machine or (user.role != "admin" and machine.owner_id != user.id):
            raise HTTPException(404, "Machine not found")
        return machine
    return guard

async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return user

async def csrf_protect(request: Request, user: User = Depends(require_user), db: DBSession = Depends(get_db)):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return user
    row = getattr(request.state, "login_session", None)
    supplied = request.headers.get("x-csrf-token")
    if not supplied and "application/x-www-form-urlencoded" in request.headers.get("content-type", ""):
        form = await request.form()
        supplied = str(form.get("csrf_token", ""))
    csrf_cookie = request.cookies.get("kestrel_csrf", "")
    if not row or not supplied or not csrf_cookie or not secrets.compare_digest(supplied, csrf_cookie) or not csrf_matches(supplied, row.csrf_hash):
        raise HTTPException(403, "CSRF validation failed")
    origin = request.headers.get("origin")
    if origin:
        expected = f"https://{settings.trusted_host}" if settings.secure_cookies else str(request.base_url).rstrip("/")
        if origin.rstrip("/") != expected:
            raise HTTPException(403, "Request origin rejected")
    return user

async def set_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
