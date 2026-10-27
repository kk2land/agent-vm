# agent-vm (macOS Apple Silicon)

A config-driven **macOS QEMU/HVF → Ubuntu 24.04 ARM64** VM launcher. Inspired by vm2api's stable per-VM identity, QCOW2 overlays and controlled egress, but runs directly on macOS (no KVM or Linux Docker dependency).

## Capabilities

- **Hardware identity**: stable per-VM MAC, UUID, disk serial, hostname, machine-id, and best-effort SMBIOS type 1 values. QEMU/virtio remains fingerprintable; this is **not** invisibility or host device anonymity.
- **Networking**: QEMU `-netdev user,restrict=on` prevents normal NAT/direct egress, even if the proxy daemon crashes. Explicit guest-to-host forwards allow only SOCKS5 TCP and a dedicated UDP-over-TCP bridge; hostfwd exposes SSH on `127.0.0.1` only. No macOS system proxy or PF changes are needed.
- **TCP + UDP**: `tun2socks` inside the Linux guest sends to a guest-local SOCKS5 shim. TCP CONNECT goes through guestfwd to the specified localhost Mihomo SOCKS5 listener. UDP ASSOCIATE datagrams are carried over a framed TCP connection to a host process, then delivered through SOCKS5 UDP ASSOCIATE. Normal UDP datagrams are supported; QUIC depends on proxy/node capabilities. SOCKS5 **must support UDP ASSOCIATE** (Mihomo mixed/SOCKS port with UDP enabled). Fragmented SOCKS5 UDP (`FRAG != 0`) is dropped, as is direct UDP if the proxy or bridge dies. ICMP is not currently proxied.
- **DNS**: `systemd-resolved` configured for strict DNS-over-TLS via the guest TUN. Custom UDP DNS can be relayed through UDP ASSOCIATE; no insecure fallback is configured.
- **Explicit read/write shares**: each configured host directory is exported via QEMU `virtio-9p-pci` and mounted in the guest. **Any shared directory is intentionally exposed to the guest and can be modified by guest processes.** Test permissions and 9P support on the target Mac/QEMU version. Do not share macOS Home, SSH keys, credentials or `/`.
- Multiple VMs have their own disk/config/SSH key, bridge port and guest hostfwd port. No password SSH auth, per-VM known_hosts.

**Status**: Scripts, tests and a loopback UDP end-to-end simulation are implemented. **Not yet run on macOS hardware**. QEMU/HVF, 9P read/write ownership behaviour, first cloud-init boot and real Mihomo UDP egress require tests on a Mac mini before calling this production ready.

## Prerequisites

- macOS Apple Silicon (M1/M2/M3/M4...) with `brew install qemu xorriso`
- Python 3.10+ (stdlib only on the host)
- A running **no-auth local** SOCKS5 listener at `127.0.0.1:7891` (configurable), with **SOCKS5 UDP ASSOCIATE** enabled. The proxy upstream must support UDP for real UDP traffic; this program never silently falls back to direct.
- Working DNS/HTTPS during `prepare` for Ubuntu ARM64 Cloud Image and pinned tun2socks archive.
- Each explicitly shared host folder must already exist and be readable/writable by the macOS user running QEMU.

## Quickstart

```bash
brew install qemu xorriso
python3 vmctl.py doctor --proxy-port 7891
python3 vmctl.py prepare

# Copy and EDIT hosts paths for folders that already exist on the Mac:
cp shares.example.json my-shares.json

python3 vmctl.py init dev1 \
  --cpus 4 --memory-mib 4096 --disk-gib 32 \
  --proxy-port 7891 --ssh-port 2222 \
  --shares-file ./my-shares.json
python3 vmctl.py start dev1
python3 vmctl.py status dev1
python3 vmctl.py ssh dev1
python3 vmctl.py stop dev1
```

Use `python3 vmctl.py start dev1 --dry-run` to review the QEMU command. VM state is in `~/.mac-vmproxy/vms/dev1/config.json` (permissions 0600); global images live in `~/.mac-vmproxy/assets/`. Override `--root /path/to/dir` before the subcommand when needed.

First boot uses cloud-init and may take time. Diagnose using `~/.mac-vmproxy/vms/dev1/serial.log`, `qemu.log`, `udp-bridge.log`, or `sudo journalctl -u vmproxy-socks -u vmproxy -u vmproxy-shares -b` inside the guest.

### Directory sharing config

`shares.example.json` is a JSON array read by `init --shares-file`:

```json
[
  { "name": "projects", "host": "/Users/agent/workspaces/tap", "guest": "/home/vmuser/projects" },
  { "name": "exchange", "host": "/Users/agent/Shared/agent-data", "guest": "/mnt/exchange" }
]
```

`name` is the QEMU 9P export label (unique), `host` is an existing macOS absolute directory and `guest` is a Linux absolute mount path. Guest paths must be below `/mnt`, `/home/vmuser` or `/opt/workspaces`. No hidden default shares; a zero-entry array disables directory sharing. The tool refuses sharing the host filesystem root and several broad system directories. **Sharing a parent that contains secrets still exposes those secrets**; only share dedicated folders.

You can modify the `shares` array inside `~/.mac-vmproxy/vms/dev1/config.json`. Power down and restart the VM to attach changed QEMU export devices, then run:

```bash
python3 vmctl.py sync-shares dev1
python3 vmctl.py ssh dev1 'findmnt -t 9p && touch /home/vmuser/projects/write-test'
```

9P file ownership/mode depends on the macOS host user and QEMU `security_model=none`; access is ultimately constrained by macOS host permissions. Some QEMU builds may not include VirtFS. If `-fsdev local` / `virtio-9p-pci` is unavailable, QEMU will fail **rather than silently turning off a configured mount**. Check `qemu-system-aarch64 -fsdev help` on the Mac. Always verify reading **and writing** to each mount before use.

### Hardware customization

`init` supports `--mac`, `--machine-uuid`, `--smbios-manufacturer`, `--smbios-product`, and `--smbios-serial`. The per-VM hardware identity is persisted in `config.json`. Editing it after first boot may desynchronize guest settings from configured MAC or machine-id. QEMU's ARM `virt` machine, virtio NIC and disk remain recognizable, regardless of SMBIOS branding.

### Network details

```text
Ubuntu applications TCP/UDP
  ↓ tun0 (tun2socks)
Guest local SOCKS5 127.0.0.1:1081
  ├─ TCP CONNECT → 10.0.2.100:1080 → QEMU guestfwd → macOS 127.0.0.1:7891
  └─ UDP ASSOCIATE → 10.0.2.101:1081 → QEMU guestfwd (TCP frames)
                                           → macOS udp_bridge.py → Mihomo SOCKS5 UDP relay
                                                → proxy node (TCP/UDP)
QEMU restrict=on blocks all other guest-to-host/outside paths.
```

The host-side bridge is bound to `127.0.0.1` on `network.udp_bridge_host_port`, autoallocated at init, and started/stopped with the VM. SOCKS5 `BND.ADDR` must point to localhost/unspecified; nonlocal UDP relay addresses are rejected. **There is no direct UDP fallback.** Changing `network.host_socks_port` needs a VM restart.

This is an isolation-oriented transport mechanism, **not** a guarantee that the proxy cannot access private IPs via its own routing rules. For strict private-network isolation, deny LAN/loopback destinations in Mihomo as appropriate and test DNS, WebRTC/STUN, UDP and IPv6. IPv6 is disabled in this first version. Also, QEMU and guest kernel bugs can defeat VM isolation; do not execute untrusted code on the same host as sensitive material without separate hardening.

### Validate proxy and shared folders

```bash
# On the Mac:
python3 vmctl.py doctor --proxy-port 7891
# In the VM:
systemctl status vmproxy-socks vmproxy vmproxy-shares
ip route
getent hosts example.com
curl https://api.ipify.org    # should report proxy exit IP
findmnt -t 9p
# After stopping Mihomo, TCP/DNS and UDP connections must FAIL, never connect directly.
```

For UDP verification use an application that does real UDP (e.g. STUN/QUIC/dig +notcp) and confirm at Mihomo's connection log that the intended UDP node handled traffic. UDP traffic may fail if that proxy/node does not support UDP; that is fail-closed behaviour.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile vmctl.py udp_bridge.py guest/socks_shim.py
```

The tests include a real loopback fake SOCKS5 UDP relay traversing Guest shim → TCP bridge → host UDP SOCKS5 relay → reverse path. They do **not** replace macOS integration tests.

## Known constraints

- Only ARM64 Linux guest, Ubuntu 24.04, macOS Apple Silicon host; no x86_64 emulation target yet.
- QEMU/libslirp UDP egress remains blocked; UDP is explicitly encapsulated inside a TCP tunnel to the host bridge. There is additional latency and possible head-of-line blocking for real-time/QUIC UDP.
- No SOCKS5 proxy authentication on the host listener (use a loopback-only Mihomo listener). No generic UDP fragmentation support.
- 9P read/write sharing may require adjusting host directory permissions, and QEMU's 9P support must be present in your Homebrew build.
- `stop` sends ACPI powerdown and waits briefly before shutting down the host bridge; VM may require another `stop` if the guest refuses to shut down.
- `sync-shares` expects SSH service to be reachable on the configured hostfwd port and Guest `vmuser` sudo privilege.