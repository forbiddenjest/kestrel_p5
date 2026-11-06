"""Shared server-rendered template environment."""
from pathlib import Path
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR), autoescape=True)

def format_uptime(seconds):
    """Render Machine.uptime() as e.g. '3d 4h', '2h 15m', '42s'; '—' when not running."""
    if seconds is None:
        return "—"
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days: return f"{days}d {hours}h"
    if hours: return f"{hours}h {minutes}m"
    if minutes: return f"{minutes}m {secs}s"
    return f"{secs}s"

templates.env.filters["uptime"] = format_uptime
