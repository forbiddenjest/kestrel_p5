# Kestrel progress 4

## Fixed
- IP allocation uses `.scalars().first()`; guest IPs skip the gateway and start at .101. Machine IDs use the full a–z0–9 alphabet.
- Node health runs real checks (libvirt reachable, forwarding on, every private IP present on the uplink, applied rules match /etc/kestrel/rules.nft, guest network active) and reports false when any fails.
- No sudo anywhere. The panel stages rules/IPs in /var/lib/kestrel/staged; a root `kestrel-rules.path` unit validates (`nft -c`) and applies them, rewrites netplan, and records the applied hash.
- `machines.html` defined blocks twice (Jinja refused to load it); blocks are now single with view switches inside.
- Remote commands were passed to asyncssh as lists; they are now shlex-joined fixed argv templates.

## Node setup script (served once at /node-setup/<token>, 15 min)
Installs packages; creates no-sudo `panel` user with the panel's SSH public key; adds private IPs to netplan (60-kestrel.yaml); enables forwarding; replaces libvirt's default network with `kestrel` (bridge kbr0, forward mode open, so only Kestrel nftables applies); writes /etc/kestrel/rules.nft (DNAT/SNAT/FORWARD, guest isolation + isolated ports); installs kestrel-node.service and kestrel-rules.path; downloads checksum-verified images/ISOs; prints health.

## VM lifecycle (worker jobs)
provision, rebuild (new image + password, same IP, confirm by VM name), delete (admin, confirm by name; frees IP, pushes rules), password (libvirt setUserPassword via guest agent), media (ISO mount/eject, boot order), firewall (per-VM allow-list), push-rules, sync-image. qcow2 overlay on base image, cloud-init seed (ubuntu user, hashed password, panel key, pinned host key, static IP, qemu-guest-agent), host-model CPU. Passwords in job payloads are Fernet-sealed and cleared after the job.

## Console
SSH to the guest IP through the node (asyncssh tunnel), user ubuntu, guest host key pinned from cloud-init.

## Not verified
Not run against a real KVM node. Migration 0002 adds new columns/table.

## Round 5
- Power buttons: `action` is now a form field; actions go through `_queue`, so a second action on the same machine while one is pending returns 409.
- Suspend: the worker reloads the machine after a power action and on reconcile, and never overwrites `suspended`. Failed power jobs leave suspended machines alone.
- First metrics sample: missing values show "—" instead of crashing.
- Worker: runs up to `worker_concurrency` jobs at once, never two for the same machine (checked both in-process and against `running` rows). Metrics and reconcile run on their own timers so they no longer block jobs.
- Uptime: every state change goes through `set_power_state()`; the Overview tab shows uptime.
- Open: `max_upload_mb` is still unused because there is no upload endpoint yet. Cluster-wide rule pushes for two machines on the same cluster can now run in parallel; each push sends the full rule set, so the last one wins and the result is still correct.
