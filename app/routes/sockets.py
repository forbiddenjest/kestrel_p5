"""Authenticated websocket SSH console: node, guest IP and pinned guest host key all come from the database."""
from datetime import timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session as DBSession
from app.db import SessionLocal
from app.config import settings
from app.models import Machine, Session as LoginSession, User, utcnow
from app.security import digest_token
from app.services.libvirt import HypervisorError, open_console
from app.services.machines import ID_RE, VM_RE

router = APIRouter()

@router.websocket("/ws/machines/{machine_id}/console")
async def console(websocket: WebSocket, machine_id: str):
    db: DBSession = SessionLocal()
    connection = process = None
    try:
        origin = websocket.headers.get("origin", "")
        expected_origin = f"https://{settings.trusted_host}" if settings.secure_cookies else f"http://{websocket.headers.get('host', '')}"
        if origin.rstrip("/") != expected_origin.rstrip("/") or not ID_RE.fullmatch(machine_id):
            await websocket.close(code=4403)
            return
        raw = websocket.cookies.get(settings.session_cookie)
        session = db.get(LoginSession, digest_token(raw)) if raw else None
        expires = session.expires_at.replace(tzinfo=timezone.utc) if session and session.expires_at.tzinfo is None else (session.expires_at if session else None)
        if not session or not session.user.active or not expires or expires <= utcnow() or session.user.force_password_change:
            await websocket.close(code=4401)
            return
        machine = db.get(Machine, machine_id)
        if not machine or (session.user.role != "admin" and machine.owner_id != session.user_id) or not VM_RE.fullmatch(machine.vm_name):
            await websocket.close(code=4403)
            return
        if machine.state != "running":
            await websocket.close(code=4409)
            return
        connection, process = await open_console(machine.cluster, machine)
        await websocket.accept()
        async def to_browser():
            while True:
                message = await process.stdout.read(4096)
                if not message:
                    break
                await websocket.send_bytes(message)
        async def to_node():
            while True:
                data = await websocket.receive_bytes()
                process.stdin.write(data)
                await process.stdin.drain()
        import asyncio
        outgoing = asyncio.create_task(to_browser())
        incoming = asyncio.create_task(to_node())
        done, pending = await asyncio.wait({outgoing, incoming}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except WebSocketDisconnect:
        pass
    except HypervisorError:
        if websocket.application_state.name == "CONNECTED":
            await websocket.close(code=1011)
    except Exception:
        if websocket.application_state.name == "CONNECTED":
            await websocket.close(code=1011)
    finally:
        if process:
            process.close()
        for item in connection or ():
            item.close()
        db.close()
