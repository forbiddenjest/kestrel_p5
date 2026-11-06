"""Validated cluster address pairs and node nftables rules."""
import ipaddress
import re
from fastapi import HTTPException

IFACE = re.compile(r"^[a-zA-Z0-9_.:-]{1,32}$")
GUEST_BRIDGE = "kbr0"
PROTOCOLS = {"tcp", "udp"}

def parse_ip_pairs(raw: str, node_subnet: str) -> list[tuple[str, str]]:
    try:
        network = ipaddress.ip_network(node_subnet, strict=False)
    except ValueError as exc:
        raise HTTPException(422, "Invalid node subnet") from exc
    pairs, seen_priv, seen_pub = [], set(), set()
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        pieces = line.strip("\r").split(",")
        if len(pieces) != 2 or any(part.strip() != part or not part for part in pieces):
            raise HTTPException(422, f"Invalid IP pair on line {number}")
        try:
            private, public = (ipaddress.ip_address(value) for value in pieces)
        except ValueError as exc:
            raise HTTPException(422, f"Invalid IPv4 address on line {number}") from exc
        if private.version != 4 or public.version != 4:
            raise HTTPException(422, "Only IPv4 addresses are supported")
        if private not in network:
            raise HTTPException(422, "Private IP must be inside the node subnet")
        if private in seen_priv or public in seen_pub:
            raise HTTPException(422, "Duplicate IP address")
        seen_priv.add(private); seen_pub.add(public); pairs.append((str(private), str(public)))
    if not pairs:
        raise HTTPException(422, "Add at least one private,public IP pair")
    return pairs

def valid_interface(name: str) -> bool:
    return bool(IFACE.fullmatch(name))

def validate_firewall_rule(protocol: str, port: int):
    if protocol not in PROTOCOLS or not 1 <= port <= 65535:
        raise HTTPException(422, "Use tcp or udp and a port between 1 and 65535")

def render_nat_rules(addresses, guest_subnet: str, interface: str, firewall: dict | None = None, bridge: str = GUEST_BRIDGE) -> str:
    """firewall maps guest IPv4 -> [(protocol, port)]; a guest with rules only accepts those inbound."""
    if not valid_interface(interface) or not valid_interface(bridge):
        raise ValueError("Invalid network interface")
    firewall = firewall or {}
    guest_network = ipaddress.ip_network(guest_subnet, strict=False)
    normalized = []
    for address in addresses:
        if hasattr(address, "private_ipv4"):
            private, guest = address.private_ipv4, address.guest_ipv4
        else:
            private, _public, guest = address
        private_ip, guest_ip = ipaddress.ip_address(private), ipaddress.ip_address(guest)
        if private_ip.version != 4 or guest_ip.version != 4 or guest_ip not in guest_network:
            raise ValueError("Address mapping does not match the configured IPv4 subnets")
        normalized.append((private_ip, guest_ip))
    lines = ["add table ip kestrel", "flush table ip kestrel", "table ip kestrel {",
             " chain prerouting { type nat hook prerouting priority dstnat; policy accept;"]
    lines += [f"  ip daddr {private} dnat to {guest}" for private, guest in normalized]
    lines += [" }", " chain postrouting { type nat hook postrouting priority srcnat; policy accept;"]
    lines += [f"  ip saddr {guest} oifname {interface} snat to {private}" for private, guest in normalized]
    lines += [" }", " chain forward { type filter hook forward priority filter; policy drop;",
              "  ct state established,related accept", "  ct state invalid drop",
              f"  ip saddr {guest_network} ip daddr {guest_network} drop"]
    for _private, guest in normalized:
        rules = firewall.get(str(guest), [])
        inbound = f"  iifname {interface} oifname {bridge} ip daddr {guest}"
        if rules:
            lines.append(f"{inbound} icmp type echo-request accept")
            for protocol, port in sorted(set(rules)):
                if protocol not in PROTOCOLS or not 1 <= int(port) <= 65535:
                    raise ValueError("Invalid firewall rule")
                lines.append(f"{inbound} {protocol} dport {int(port)} accept")
        else:
            lines.append(f"{inbound} accept")
        lines.append(f"  iifname {bridge} oifname {interface} ip saddr {guest} accept")
    lines += [" }", "}"]
    return "\n".join(lines) + "\n"
