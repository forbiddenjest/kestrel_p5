"""Server-side guarded administrator operations."""
import ipaddress, json, secrets
from datetime import timedelta
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession
from app.config import settings
from app.db import get_db
from app.deps import csrf_protect, require_admin
from app.web import templates
from app.models import AuditLog, Cluster, ClusterIP, Image, Job, Machine, User, utcnow
from app.security import encrypt_node_key, hash_password
from app.security import digest_token
from app.services.clusters import issue_setup_token, node_subnet, render_setup_script, validate_cluster
from app.services.machines import allocate_ip, new_guest_password, new_machine_id, new_vm_name, next_guest_address, validate_specs
from app.worker import seal
from app.services.network import parse_ip_pairs
from app.services.images import validate_image_url
from app.services.libvirt import verify_node

router = APIRouter(prefix="/administrator", dependencies=[Depends(require_admin)])
# Node enrollment endpoint: authenticated only by the one-time, 15-minute setup token.
node_router = APIRouter()
PAGES = {"overview", "machines", "users", "clusters", "networking", "images", "logs"}

def context(request, user, db, page, **extra):
    data = {"user": user, "page": page, "csrf_token": getattr(request.state, "csrf_token", ""), "machines": db.query(Machine).all(), "users": db.query(User).all(), "clusters": db.query(Cluster).all(), "ips": db.query(ClusterIP).all(), "images": db.query(Image).all(), "jobs": db.query(Job).order_by(Job.created_at.desc()).limit(100).all(), "logs": db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all(), "flash": "", "notice": ""}
    data.update(extra)
    return data

def record(db, actor, request, action, target=""):
    db.add(AuditLog(actor_id=actor.id, action=action, target=target, remote_ip=request.client.host if request.client else "", result="ok"))

@router.get("/{page}")
def admin_page(page: str, request: Request, user: User = Depends(require_admin), db: DBSession = Depends(get_db)):
    if page not in PAGES:
        raise HTTPException(404, "Page not found")
    return templates.TemplateResponse(request, f"administrator/{page}.html", context(request, user, db, page))

@router.post("/users")
def create_user(request: Request, email: str = Form(...), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    email = email.strip().lower()
    if "@" not in email or db.query(User).filter(User.email == email).first():
        raise HTTPException(422, "Enter a unique email address")
    temporary_password = secrets.token_urlsafe(18)
    user = User(email=email, password_hash=hash_password(temporary_password), role="user", force_password_change=True)
    db.add(user); db.flush(); record(db, actor, request, "user.create", str(user.id)); db.commit()
    return templates.TemplateResponse(request, "administrator/users.html", context(request, actor, db, "users", flash=f"User created. Temporary password: {temporary_password}"))

@router.post("/users/{user_id}/toggle")
def toggle_user(user_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    target = db.get(User, user_id)
    if not target or target.id == actor.id:
        raise HTTPException(404, "User not found")
    target.active = not target.active; record(db, actor, request, "user.toggle", str(user_id)); db.commit()
    return RedirectResponse("/administrator/users", status_code=303)

@router.post("/clusters")
def create_cluster(request: Request, name: str = Form(...), node_ipv4: str = Form(...), ssh_port: int = Form(22), guest_subnet: str = Form(...), uplink_interface: str = Form(...), pairs: str = Form(...), ssh_private_key: str = Form(...), node_host_key: str = Form(...), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if db.query(Cluster).filter(Cluster.name == name.strip()).first():
        raise HTTPException(409, "Cluster name already exists")
    try:
        validate_cluster(node_ipv4, ssh_port, guest_subnet, uplink_interface)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    try:
        import asyncssh
        asyncssh.import_known_hosts(node_host_key)
    except Exception as exc:
        raise HTTPException(422, "Enter a valid OpenSSH known_hosts entry for this node") from exc
    ip_pairs = parse_ip_pairs(pairs, str(ipaddress.ip_interface(node_ipv4 + "/24").network))
    try:
        from app.services.libvirt import panel_public_key
        panel_public_key(ssh_private_key)
    except Exception as exc:
        raise HTTPException(422, "Enter a valid unencrypted OpenSSH private key for the panel") from exc
    token = secrets.token_urlsafe(32)
    cluster = Cluster(name=name.strip(), node_ipv4=node_ipv4, ssh_port=ssh_port, guest_subnet=guest_subnet, uplink_interface=uplink_interface, ssh_key_encrypted=encrypt_node_key(ssh_private_key), node_host_key=node_host_key, state="pending")
    db.add(cluster); db.flush()
    for private, public in ip_pairs:
        db.add(ClusterIP(cluster_id=cluster.id, private_ipv4=private, public_ipv4=public, guest_ipv4=next_guest_address(db, cluster)))
        db.flush()
    setup_token = issue_setup_token(cluster)
    record(db, actor, request, "cluster.create", str(cluster.id)); db.commit()
    return templates.TemplateResponse(request, "administrator/clusters.html", context(request, actor, db, "clusters", flash=setup_command(setup_token)))

def setup_command(token: str) -> str:
    return f"curl -fsSL https://{settings.trusted_host}/node-setup/{token} | sudo bash"

@router.post("/clusters/{cluster_id}/token")
def reissue_token(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    token = issue_setup_token(cluster); record(db, actor, request, "cluster.token", str(cluster_id)); db.commit()
    return templates.TemplateResponse(request, "administrator/clusters.html", context(request, actor, db, "clusters", flash=setup_command(token)))

@router.post("/clusters/{cluster_id}/verify")
async def verify_cluster(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    try:
        checks = await verify_node(cluster)
    except Exception:
        checks = {}
    passed = bool(checks) and all(checks.values())
    if passed:
        import asyncio
        from app.services.libvirt import node_capacity
        try:
            cluster.cpu_capacity, cluster.memory_capacity_mb = await asyncio.to_thread(node_capacity, cluster)
        except Exception:
            pass
        cluster.state = "active"
    db.add(AuditLog(actor_id=actor.id, action="cluster.verify", target=str(cluster_id), remote_ip=request.client.host if request.client else "", result="ok" if passed else "failed"))
    db.commit()
    failed = ", ".join(k for k, v in checks.items() if not v) or "node unreachable"
    message = "Cluster verified and active." if passed else f"Verification failed: {failed}."
    return templates.TemplateResponse(request, "administrator/clusters.html", context(request, actor, db, "clusters", notice=message))

@node_router.get("/node-setup/{token}", response_class=PlainTextResponse)
def node_setup(token: str, db: DBSession = Depends(get_db)):
    if not 20 <= len(token) <= 64:
        raise HTTPException(404, "Not found")
    cluster = db.query(Cluster).filter(Cluster.setup_token_hash == digest_token(token)).first()
    expires = cluster.setup_token_expires if cluster else None
    if expires is not None and expires.tzinfo is None:
        from datetime import timezone
        expires = expires.replace(tzinfo=timezone.utc)
    if not cluster or not expires or expires <= utcnow():
        raise HTTPException(404, "Not found")
    cluster.setup_token_hash = None; cluster.setup_token_expires = None  # one-time
    db.add(AuditLog(action="cluster.setup_fetched", target=str(cluster.id), result="ok"))
    script = render_setup_script(db, cluster)
    db.commit()
    return PlainTextResponse(script, headers={"Cache-Control": "no-store"})

@router.post("/machines")
def create_machine(request: Request, owner_id: int = Form(...), cluster_id: int = Form(...), image_id: int = Form(...), vcpu: int = Form(...), memory_mb: int = Form(...), disk_gb: int = Form(...), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    validate_specs(vcpu, memory_mb, disk_gb)
    owner, cluster, image = db.get(User, owner_id), db.get(Cluster, cluster_id), db.get(Image, image_id)
    if not owner or not owner.active or not cluster or cluster.state != "active" or not image or not image.active:
        raise HTTPException(422, "Select an active owner, cluster, and image")
    address = allocate_ip(db, cluster_id)
    machine_id = new_machine_id(db)
    vm_name = new_vm_name(db)
    if image.kind != "cloud":
        raise HTTPException(422, "Machines are built from cloud images")
    password = new_guest_password()
    machine = Machine(id=machine_id, vm_name=vm_name, owner_id=owner_id, cluster_id=cluster_id, image_id=image_id, vcpu=vcpu, memory_mb=memory_mb, disk_gb=disk_gb)
    address.machine_id = machine.id
    db.add(machine)
    db.flush()
    db.add(Job(kind="provision", machine_id=machine.id, actor_id=actor.id, payload=seal({"password": password}), state="queued"))
    record(db, actor, request, "machine.create", machine.id); db.commit()
    return templates.TemplateResponse(request, "administrator/machines.html", context(request, actor, db, "machines", flash=f"{machine.id} queued. Login: ubuntu / {password}"))

@router.post("/machines/{machine_id}/delete")
def delete_machine(machine_id: str, request: Request, confirm_name: str = Form(...), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = db.get(Machine, machine_id)
    if not machine:
        raise HTTPException(404, "Machine not found")
    if confirm_name != machine.vm_name:
        raise HTTPException(422, "Type the machine name exactly to confirm")
    if db.query(Job.id).filter(Job.machine_id == machine.id, Job.state.in_(["queued", "running"])).first():
        raise HTTPException(409, "Another operation is pending for this machine")
    machine.state = "deleting"
    db.add(Job(kind="delete", machine_id=machine.id, actor_id=actor.id, state="queued"))
    record(db, actor, request, "machine.delete", machine.id); db.commit()
    return RedirectResponse("/administrator/machines", status_code=303)

@router.post("/machines/{machine_id}/suspend")
def suspend_machine(machine_id: str, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    machine = db.get(Machine, machine_id)
    if not machine or machine.state in {"provisioning", "rebuilding", "deleting"}:
        raise HTTPException(404, "Machine not found")
    if machine.state == "suspended":
        machine.set_power_state("stopped")
    else:
        machine.set_power_state("suspended")
        db.add(Job(kind="force-stop", machine_id=machine.id, actor_id=actor.id, state="queued"))
    record(db, actor, request, "machine.suspend", machine.id); db.commit()
    return RedirectResponse("/administrator/machines", status_code=303)

@router.post("/images")
def create_image(request: Request, name: str = Form(...), url: str = Form(...), checksum: str = Form(...), kind: str = Form("cloud"), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    if kind not in {"cloud", "iso"} or not validate_image_url(url, checksum):
        raise HTTPException(422, "Use a secure image URL and a valid SHA-256 checksum")
    image = Image(name=name.strip(), url=url, checksum=checksum.lower(), kind=kind)
    db.add(image); db.flush()
    for cluster in db.query(Cluster).filter(Cluster.state == "active").all():
        db.add(Job(kind="sync-image", actor_id=actor.id, state="queued", payload=json.dumps({"image_id": image.id, "cluster_id": cluster.id})))
    record(db, actor, request, "image.create", str(image.id)); db.commit()
    return RedirectResponse("/administrator/images", status_code=303)

@router.post("/networking/ips")
def add_ips(request: Request, cluster_id: int = Form(...), pairs: str = Form(...), actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    parsed = parse_ip_pairs(pairs, node_subnet(cluster))
    existing = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster_id).all()
    private, public = {ip.private_ipv4 for ip in existing}, {ip.public_ipv4 for ip in existing}
    if any(a in private or b in public for a, b in parsed):
        raise HTTPException(409, "An address is already in this cluster")
    for private_ip, public_ip in parsed:
        guest_ip = next_guest_address(db, cluster)
        db.add(ClusterIP(cluster_id=cluster_id, private_ipv4=private_ip, public_ipv4=public_ip, guest_ipv4=guest_ip))
        db.flush()
    if cluster.state in {"active", "draining"}:
        db.add(Job(kind="push-rules", actor_id=actor.id, state="queued", payload=json.dumps({"cluster_id": cluster.id})))
    record(db, actor, request, "network.ips.add", str(cluster_id)); db.commit()
    return RedirectResponse("/administrator/networking", status_code=303)

@router.post("/clusters/{cluster_id}/drain")
def drain_cluster(cluster_id: int, request: Request, actor: User = Depends(csrf_protect), db: DBSession = Depends(get_db)):
    cluster = db.get(Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "Cluster not found")
    cluster.state = "draining"; record(db, actor, request, "cluster.drain", str(cluster_id)); db.commit()
    return RedirectResponse("/administrator/clusters", status_code=303)
