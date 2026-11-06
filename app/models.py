"""Persistent models; identifiers and node state are never trusted from request data."""
from datetime import datetime, timezone
from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db import Base

def utcnow(): return datetime.now(timezone.utc)

# 64-bit on Postgres; SQLite only autoincrements a plain INTEGER primary key (which is 64-bit there anyway).
BigID = BigInteger().with_variant(Integer, "sqlite")

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="user")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    force_password_change: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sessions: Mapped[list["Session"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    machines: Mapped[list["Machine"]] = relationship(back_populates="owner")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_key: Mapped[str] = mapped_column(String(64), index=True)
    ip_key: Mapped[str] = mapped_column(String(64), index=True)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user: Mapped[User] = relationship(back_populates="sessions")

class Cluster(Base):
    __tablename__ = "clusters"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    node_ipv4: Mapped[str] = mapped_column(String(45))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    guest_subnet: Mapped[str] = mapped_column(String(43))
    uplink_interface: Mapped[str] = mapped_column(String(32))
    ssh_key_encrypted: Mapped[str] = mapped_column(Text)
    node_host_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="pending")
    setup_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    setup_token_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cpu_capacity: Mapped[int] = mapped_column(Integer, default=0)
    memory_capacity_mb: Mapped[int] = mapped_column(Integer, default=0)
    disk_capacity_gb: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ips: Mapped[list["ClusterIP"]] = relationship(back_populates="cluster", cascade="all, delete-orphan")
    machines: Mapped[list["Machine"]] = relationship(back_populates="cluster")

class ClusterIP(Base):
    __tablename__ = "cluster_ips"
    __table_args__ = (UniqueConstraint("cluster_id", "private_ipv4"), UniqueConstraint("cluster_id", "public_ipv4"), UniqueConstraint("cluster_id", "guest_ipv4"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="CASCADE"), index=True)
    private_ipv4: Mapped[str] = mapped_column(String(45))
    public_ipv4: Mapped[str] = mapped_column(String(45))
    guest_ipv4: Mapped[str] = mapped_column(String(45))
    machine_id: Mapped[str | None] = mapped_column(ForeignKey("machines.id", ondelete="SET NULL"), nullable=True, unique=True)
    cluster: Mapped[Cluster] = relationship(back_populates="ips")

class Image(Base):
    __tablename__ = "images"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    url: Mapped[str] = mapped_column(Text)
    checksum: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16), default="cloud")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Machine(Base):
    __tablename__ = "machines"
    id: Mapped[str] = mapped_column(String(8), primary_key=True)
    vm_name: Mapped[str] = mapped_column(String(16), unique=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    cluster_id: Mapped[int] = mapped_column(ForeignKey("clusters.id", ondelete="RESTRICT"), index=True)
    image_id: Mapped[int | None] = mapped_column(ForeignKey("images.id", ondelete="SET NULL"), nullable=True)
    vcpu: Mapped[int] = mapped_column(Integer)
    memory_mb: Mapped[int] = mapped_column(Integer)
    disk_gb: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default="provisioning")
    uptime_seconds: Mapped[int] = mapped_column(Integer, default=0)  # legacy, unused; see started_at
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    guest_host_key: Mapped[str | None] = mapped_column(Text, nullable=True)  # pinned guest SSH host public key
    iso_image_id: Mapped[int | None] = mapped_column(ForeignKey("images.id", ondelete="SET NULL"), nullable=True)
    boot_device: Mapped[str] = mapped_column(String(8), default="disk")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    owner: Mapped[User] = relationship(back_populates="machines")
    cluster: Mapped[Cluster] = relationship(back_populates="machines")
    image: Mapped["Image | None"] = relationship(foreign_keys=[image_id])
    iso: Mapped["Image | None"] = relationship(foreign_keys=[iso_image_id])
    firewall_rules: Mapped[list["FirewallRule"]] = relationship(back_populates="machine", cascade="all, delete-orphan")
    cluster_ip: Mapped[ClusterIP | None] = relationship(backref="machine", uselist=False, primaryjoin="Machine.id == ClusterIP.machine_id")

    def uptime(self) -> int | None:
        """Seconds since the panel last saw this machine start; None when not running."""
        if self.state != "running" or not self.started_at:
            return None
        started = self.started_at if self.started_at.tzinfo else self.started_at.replace(tzinfo=timezone.utc)
        return max(0, int((utcnow() - started).total_seconds()))

    def set_power_state(self, state: str):
        """Single place that moves state and keeps started_at consistent with it."""
        if state == "running" and (self.state != "running" or not self.started_at):
            self.started_at = utcnow()
        elif state != "running":
            self.started_at = None
        self.state = state

class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    __table_args__ = (UniqueConstraint("machine_id", "protocol", "port"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    machine_id: Mapped[str] = mapped_column(ForeignKey("machines.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(4))
    port: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    machine: Mapped[Machine] = relationship(back_populates="firewall_rules")

class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    machine_id: Mapped[str | None] = mapped_column(ForeignKey("machines.id", ondelete="SET NULL"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    payload: Mapped[str] = mapped_column(Text, default="{}")
    state: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class MetricSample(Base):
    __tablename__ = "metric_samples"
    __table_args__ = (Index("ix_metric_machine_time", "machine_id", "sampled_at"),)
    id: Mapped[int] = mapped_column(BigID, primary_key=True)
    machine_id: Mapped[str] = mapped_column(ForeignKey("machines.id", ondelete="CASCADE"), index=True)
    cpu_percent: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)
    cpu_time_ns: Mapped[int] = mapped_column(BigInteger, default=0)
    memory_used_mb: Mapped[int] = mapped_column(Integer, default=0)
    disk_read_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_write_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    network_rx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    network_tx_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sampled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    target: Mapped[str] = mapped_column(String(160), default="")
    remote_ip: Mapped[str] = mapped_column(String(45), default="")
    result: Mapped[str] = mapped_column(String(20), default="ok")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
