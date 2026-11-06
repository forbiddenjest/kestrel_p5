"""Cluster enrollment, setup script rendering and node rule assembly."""
import ipaddress, secrets
from datetime import timedelta
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from app.models import ClusterIP, FirewallRule, Image, Machine, utcnow
from app.security import decrypt_node_key, digest_token
from app.services.machines import guest_gateway
from app.services.network import GUEST_BRIDGE, render_nat_rules, valid_interface

NODE_DIR = Path(__file__).resolve().parents[2] / "node"
# Shell output, not HTML: autoescape off. Every interpolated value is validated or passed through |q.
_env = Environment(loader=FileSystemLoader(str(NODE_DIR)), autoescape=False, undefined=StrictUndefined, keep_trailing_newline=True)
import shlex
_env.filters["q"] = shlex.quote

def validate_cluster(node_ipv4: str, ssh_port: int, guest_subnet: str, uplink_interface: str):
    node = ipaddress.ip_address(node_ipv4); subnet = ipaddress.ip_network(guest_subnet, strict=False)
    if node.version != 4 or subnet.version != 4: raise ValueError("IPv4 is required")
    if not 1 <= ssh_port <= 65535: raise ValueError("Invalid SSH port")
    if not valid_interface(uplink_interface): raise ValueError("Invalid uplink interface")
    if subnet.prefixlen > 28: raise ValueError("Guest subnet is too small")

def issue_setup_token(cluster):
    token = secrets.token_urlsafe(32)
    cluster.setup_token_hash = digest_token(token)
    cluster.setup_token_expires = utcnow() + timedelta(minutes=15)
    return token

def node_subnet(cluster) -> str:
    return str(ipaddress.ip_interface(cluster.node_ipv4 + "/24").network)

def secondary_private_ips(db, cluster) -> list[str]:
    rows = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id).order_by(ClusterIP.id).all()
    return [row.private_ipv4 for row in rows if row.private_ipv4 != cluster.node_ipv4]

def cluster_rules(db, cluster) -> str:
    addresses = db.query(ClusterIP).filter(ClusterIP.cluster_id == cluster.id).order_by(ClusterIP.id).all()
    firewall: dict[str, list] = {}
    rows = (db.query(ClusterIP.guest_ipv4, FirewallRule.protocol, FirewallRule.port)
            .join(Machine, Machine.id == ClusterIP.machine_id).join(FirewallRule, FirewallRule.machine_id == Machine.id)
            .filter(ClusterIP.cluster_id == cluster.id).all())
    for guest, protocol, port in rows:
        firewall.setdefault(guest, []).append((protocol, port))
    return render_nat_rules(addresses, cluster.guest_subnet, cluster.uplink_interface, firewall)

def render_setup_script(db, cluster) -> str:
    from app.services.libvirt import panel_public_key
    network = ipaddress.ip_network(cluster.guest_subnet, strict=False)
    images = db.query(Image).filter(Image.active.is_(True)).order_by(Image.id).all()
    return _env.get_template("setup.sh.j2").render(
        uplink=cluster.uplink_interface, bridge=GUEST_BRIDGE, node_prefix=24,
        private_ips=secondary_private_ips(db, cluster), rules=cluster_rules(db, cluster),
        panel_key=panel_public_key(decrypt_node_key(cluster.ssh_key_encrypted)),
        gateway=guest_gateway(cluster.guest_subnet), guest_prefix=network.prefixlen, guest_netmask=str(network.netmask),
        images=[{"id": int(i.id), "kind": i.kind, "url": i.url, "sha": i.checksum} for i in images],
        node_service=(NODE_DIR / "kestrel-node.service").read_text(encoding="utf-8"),
    )
