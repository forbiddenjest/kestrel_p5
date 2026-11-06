#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
apt-get update
apt-get install -y python3.12 python3.12-venv python3-pip build-essential pkg-config libvirt-dev libvirt-daemon-system libvirt-clients qemu-utils caddy
getent group kestrel >/dev/null || groupadd --system kestrel
id -u kestrel >/dev/null 2>&1 || useradd --system --gid kestrel --home-dir /var/lib/kestrel --create-home --shell /usr/sbin/nologin kestrel
install -d -o kestrel -g kestrel -m 0750 /var/lib/kestrel /var/lib/kestrel/media
install -d -o root -g kestrel -m 0750 /etc/kestrel
python3.12 -m venv /opt/kestrel/.venv
/opt/kestrel/.venv/bin/pip install --upgrade pip==25.1.1
/opt/kestrel/.venv/bin/pip install /opt/kestrel
/opt/kestrel/.venv/bin/python -m app.setup init-env
install -m 0640 -o root -g kestrel /opt/kestrel/.env /etc/kestrel/kestrel.env
chown root:kestrel /opt/kestrel/.env
chmod 0640 /opt/kestrel/.env
chown -R kestrel:kestrel /opt/kestrel
runuser -u kestrel -- sh -c 'cd /opt/kestrel && .venv/bin/alembic -c alembic.ini upgrade head'
install -m 0644 /opt/kestrel/deploy/kestrel.service /etc/systemd/system/
install -m 0644 /opt/kestrel/deploy/kestrel-worker.service /etc/systemd/system/
systemctl daemon-reload
echo "Install files are in place. Set KESTREL_TRUSTED_HOST in /etc/kestrel/kestrel.env, then create an administrator from /opt/kestrel with: sudo -u kestrel sh -c "cd /opt/kestrel && .venv/bin/python -m app.setup create-admin you@example.com""
echo "For production, install deploy/Caddyfile as the Caddy configuration and configure the hostname in deploy/Caddyfile."
