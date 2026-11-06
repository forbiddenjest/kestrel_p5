"""Kestrel application entry point."""
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.config import settings
from app.deps import set_security_headers
from app.routes import account, administrator, auth, machines, sockets
from app.web import templates

ROOT = Path(__file__).resolve().parent
app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, openapi_url=None)
allowed_hosts = ["*"] if settings.environment == "development" else [settings.trusted_host, "localhost", "127.0.0.1"]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)
app.middleware("http")(set_security_headers)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
app.include_router(auth.router)
app.include_router(account.router)
app.include_router(machines.router)
app.include_router(administrator.router)
app.include_router(administrator.node_router)
app.include_router(sockets.router)

@app.get("/", include_in_schema=False)
async def home():
    return RedirectResponse("/auth", status_code=303)

@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if exc.status_code in {401, 303} and exc.headers and exc.headers.get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=exc.status_code)
    if exc.status_code == 401:
        return RedirectResponse("/auth", status_code=303)
    if exc.status_code in {403, 404, 500}:
        return templates.TemplateResponse(request, "errors.html", {"status": exc.status_code, "message": exc.detail}, status_code=exc.status_code)
    return templates.TemplateResponse(request, "errors.html", {"status": exc.status_code, "message": "The request could not be completed."}, status_code=exc.status_code)

@app.exception_handler(500)
async def server_error(request: Request, exc):
    return templates.TemplateResponse(request, "errors.html", {"status": 500, "message": "The request could not be completed."}, status_code=500)
