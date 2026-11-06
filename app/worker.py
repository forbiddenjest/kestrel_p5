"""Database-backed queue worker. Only a single service instance should run."""
import asyncio
import json
from datetime import timedelta
from sqlalchemy import update
from app.config import settings
from app.db import SessionLocal
from app.models import AuditLog, Cluster, ClusterIP, Image, Job, Machine, MetricSample, utcnow
from app.security import decrypt_node_key, encrypt_node_key
from app.services import libvirt as hv
from app.services.clusters import cluster_rules, secondary_private_ips
from app.services.libvirt import HypervisorError, domain_status, power_action
from app.services.machines import guest_gateway
from app.services.metrics import collect_machine_metrics, purge_metrics

JOB_TIMEOUT = 1800

def seal(data: dict) -> str:
    """Job payloads may carry a guest password; keep them encrypted at rest."""
    return json.dumps({"sealed": encrypt_node_key(json.dumps(data))})

def unseal(payload: str) -> dict:
    raw = json.loads(payload or "{}")
    return json.loads(decrypt_node_key(raw["sealed"])) if "sealed" in raw else raw

def machine_spec(machine) -> dict:
    ip = machine.cluster_ip
    if not ip: raise RuntimeError("Machine has no assigned address")
    return {"vm_name": machine.vm_name, "hostname": machine.id, "vcpu": machine.vcpu, "memory_mb": machine.memory_mb,
            "disk_gb": machine.disk_gb, "image_id": machine.image_id, "guest_ip": ip.guest_ipv4,
            "guest_subnet": machine.cluster.guest_subnet, "gateway": guest_gateway(machine.cluster.guest_subnet),
            "iso_image_id": machine.iso_image_id, "boot_device": machine.boot_device}

async def _push_cluster_rules(db, cluster):
    await hv.push_rules(cluster, cluster_rules(db, cluster), secondary_private_ips(db, cluster))

async def _execute(db, job, machine, data):
    kind = job.kind
    if kind in {"start", "stop", "restart", "force-stop"} and machine:
        result = await asyncio.to_thread(power_action, machine.cluster, machine.vm_name, kind)
        db.refresh(machine)  # an admin may have suspended it while the action ran
        if machine.state != "suspended":
            machine.set_power_state(result)
        return "Machine action completed"
    if kind in {"provision", "rebuild"} and machine:
        if not machine.image or machine.image.kind != "cloud" or not machine.image.active:
            raise RuntimeError("Machine image is not an active cloud image")
        if kind == "rebuild":
            machine.image_id = int(data["image_id"]); db.flush(); db.refresh(machine)
        action = hv.provision if kind == "provision" else hv.rebuild
        machine.guest_host_key = await action(machine.cluster, machine_spec(machine), data["password"])
        await _push_cluster_rules(db, machine.cluster)
        machine.set_power_state("running")
        return "Machine built" if kind == "provision" else "Machine rebuilt"
    if kind == "delete" and machine:
        cluster = machine.cluster
        await hv.delete(cluster, machine.vm_name)
        address = db.query(ClusterIP).filter(ClusterIP.machine_id == machine.id).first()
        if address: address.machine_id = None
        job.machine_id = None
        db.delete(machine); db.flush()
        await _push_cluster_rules(db, cluster)
        return "Machine deleted"
    if kind == "password" and machine:
        await asyncio.to_thread(hv.set_guest_password, machine.cluster, machine.vm_name, data["password"])
        return "Guest password updated"
    if kind == "media" and machine:
        await asyncio.to_thread(hv.set_media, machine.cluster, machine_spec(machine))
        return "Media updated"
    if kind == "firewall" and machine:
        await _push_cluster_rules(db, machine.cluster)
        return "Firewall rules applied"
    if kind == "push-rules":
        cluster = db.get(Cluster, int(data["cluster_id"]))
        await _push_cluster_rules(db, cluster)
        return "Node rules applied"
    if kind == "sync-image":
        image, cluster = db.get(Image, int(data["image_id"])), db.get(Cluster, int(data["cluster_id"]))
        await hv.sync_image(cluster, image)
        return "Image synced"
    raise RuntimeError("Unsupported operation")

async def _run_job(job_id: int):
    db = SessionLocal()
    job = None
    try:
        job = db.get(Job, job_id)
        if not job:
            return
        machine = db.get(Machine, job.machine_id) if job.machine_id else None
        data = unseal(job.payload)
        job.result = await asyncio.wait_for(_execute(db, job, machine, data), timeout=JOB_TIMEOUT)
        job.state = "complete"; job.payload = "{}"
        db.add(AuditLog(actor_id=job.actor_id, action=f"job.{job.kind}", target=job.machine_id or str(job_id), result="ok"))
    except Exception as exc:
        db.rollback()
        job = db.get(Job, job_id)
        if job:
            job.state = "failed"; job.payload = "{}"
            job.result = (str(exc) or type(exc).__name__)[:500]
            failed_machine = db.get(Machine, job.machine_id) if job.machine_id else None
            if failed_machine and job.kind in {"provision", "rebuild"}:
                failed_machine.state = "failed"
            elif failed_machine and job.kind in {"start", "stop", "restart", "force-stop"} and failed_machine.state != "suspended":
                failed_machine.set_power_state("unknown")
        db.add(AuditLog(actor_id=job.actor_id if job else None, action=f"job.{job.kind if job else 'unknown'}", target=(job.machine_id or str(job_id)) if job else str(job_id), result="failed"))
    finally:
        if job is not None:
            job.updated_at = utcnow()
        db.commit()
        db.close()

def _claim_next(db, busy_machines: set):
    """Claim the oldest queued job whose machine has no other job in flight."""
    now = utcnow()
    in_flight = db.query(Job.machine_id).filter(Job.state == "running", Job.machine_id.isnot(None))
    query = db.query(Job.id, Job.machine_id).filter(Job.state == "queued").filter(
        (Job.machine_id.is_(None)) | (Job.machine_id.notin_(in_flight)))
    if busy_machines:
        query = query.filter((Job.machine_id.is_(None)) | (Job.machine_id.notin_(busy_machines)))
    candidate = query.order_by(Job.created_at).first()
    if not candidate:
        return None, None
    job_id, machine_id = candidate
    changed = db.execute(update(Job).where(Job.id == job_id, Job.state == "queued").values(state="running", updated_at=now)).rowcount
    db.commit()
    return (job_id, machine_id) if changed == 1 else (None, None)

def _requeue_stale(db):
    cutoff = utcnow() - timedelta(seconds=JOB_TIMEOUT + 60)
    db.query(Job).filter(Job.state == "running", Job.updated_at < cutoff).update({Job.state: "queued", Job.updated_at: utcnow()}, synchronize_session=False)

async def _poll_metrics():
    db = SessionLocal()
    try:
        running = db.query(Machine).filter(Machine.state == "running").all()
        for machine in running:
            try:
                previous = db.query(MetricSample).filter(MetricSample.machine_id == machine.id).order_by(MetricSample.sampled_at.desc()).first()
                values = await asyncio.to_thread(collect_machine_metrics, machine.cluster, machine.vm_name, previous)
                if values:
                    db.add(MetricSample(machine_id=machine.id, **values))
            except Exception:
                continue
        db.commit()
        purge_metrics(db)
        db.commit()
    finally:
        db.close()

async def _reconcile():
    db = SessionLocal()
    try:
        machines = db.query(Machine).filter(Machine.state.notin_(["provisioning", "rebuilding", "deleting", "failed", "suspended"])).all()
        for machine in machines:
            try:
                current = await asyncio.to_thread(domain_status, machine.cluster, machine.vm_name)
                if current in {"running", "stopped"} and machine.state in {"running", "stopped", "starting", "stopping", "restarting", "unknown"}:
                    db.refresh(machine)
                    if machine.state != "suspended":
                        machine.set_power_state(current)
            except Exception:
                continue
        db.commit()
    finally:
        db.close()

async def _periodic(fn, interval_fn):
    """Run fn forever on its own schedule so a slow pass never blocks job dispatch."""
    while True:
        try:
            await fn()
        except Exception:
            pass
        await asyncio.sleep(interval_fn())

async def worker_loop():
    """Dispatch up to worker_concurrency jobs at once, never two for the same machine."""
    slots = asyncio.Semaphore(settings.worker_concurrency)
    busy_machines: set[str] = set()
    tasks: set[asyncio.Task] = set()
    background = [
        asyncio.create_task(_periodic(_poll_metrics, lambda: settings.metrics_interval_seconds)),
        asyncio.create_task(_periodic(_reconcile, lambda: 30)),
    ]

    async def run(job_id, machine_id):
        try:
            await _run_job(job_id)
        finally:
            if machine_id: busy_machines.discard(machine_id)
            slots.release()

    try:
        while True:
            await slots.acquire()
            db = SessionLocal()
            try:
                _requeue_stale(db); db.commit()
                job_id, machine_id = _claim_next(db, busy_machines)
            except Exception:
                job_id, machine_id = None, None
            finally:
                db.close()
            if job_id is None:
                slots.release()
                await asyncio.sleep(settings.worker_interval_seconds)
                continue
            if machine_id: busy_machines.add(machine_id)
            task = asyncio.create_task(run(job_id, machine_id))
            tasks.add(task); task.add_done_callback(tasks.discard)
    finally:
        for task in background: task.cancel()
