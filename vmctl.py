#!/usr/bin/env python3
"""mac-vmproxy: macOS Apple Silicon QEMU/HVF ARM64 VM with fail-closed SOCKS5 egress.

Python stdlib only; external macOS tools: qemu-system-aarch64, qemu-img,
qemu/EDK2 firmware, xorriso, ssh-keygen, ssh.
"""
from __future__ import annotations

import argparse
import shlex
import hashlib
import io
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = Path.home() / ".mac-vmproxy"
UBUNTU_URL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
UBUNTU_SUMS_URL = "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
UBUNTU_IMAGE_NAME = "noble-server-cloudimg-arm64.img"
TUN_VERSION = "v2.7.0"
TUN_URL = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.7.0/tun2socks-linux-arm64.zip"
TUN_ARCHIVE_SHA256 = "3931476c9cfa8fa236d23aeaf36767df0eb27cc11ecaab699faba57744450f49"
PROXY_GUEST_IP = "10.0.2.100"
PROXY_GUEST_PORT = 1080
UDP_BRIDGE_GUEST_IP = "10.0.2.101"
UDP_BRIDGE_GUEST_PORT = 1081
ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")


class VMError(Exception):
    pass


def note(msg: str) -> None:
    print(msg, flush=True)


def cmd(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, text=True, **kwargs)


def ensure_macos() -> None:
    if sys.platform != "darwin" or platform.machine().lower() not in ("arm64", "aarch64"):
        raise VMError("This implementation requires macOS on Apple Silicon (arm64). On other systems use tests only.")


def safe_name(name: str) -> str:
    if not ID_RE.fullmatch(name):
        raise VMError("VM name must match [a-z][a-z0-9-]{0,30}")
    return name


def vm_dir(root: Path, name: str) -> Path:
    return root / "vms" / safe_name(name)


def mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def write_private(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)


def read_config(root: Path, name: str) -> tuple[Path, dict]:
    folder = vm_dir(root, name)
    try:
        obj = json.loads((folder / "config.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise VMError(f"Cannot read VM config: {folder / 'config.json'} ({e})") from e
    if obj.get("name") != name or obj.get("architecture") != "aarch64":
        raise VMError("Corrupt VM config")
    return folder, obj


def sha256_file(path: Path) -> str:
    dig = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            dig.update(chunk)
    return dig.hexdigest()


def download(url: str, destination: Path, *, expected_sha256: str) -> None:
    mkdir_private(destination.parent)
    if destination.exists() and sha256_file(destination) == expected_sha256:
        return
    tmp = destination.with_name(destination.name + ".download")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mac-vmproxy/0.1"})
        with urllib.request.urlopen(req, timeout=45) as src, tmp.open("wb") as out:
            shutil.copyfileobj(src, out)
        actual = sha256_file(tmp)
        if actual.lower() != expected_sha256.lower():
            raise VMError(f"SHA256 mismatch for {url}\n expected {expected_sha256}\n got      {actual}")
        tmp.replace(destination)
    finally:
        tmp.unlink(missing_ok=True)


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "mac-vmproxy/0.1"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8")


def ubuntu_sha256(manifest: str) -> str:
    for line in manifest.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and Path(parts[-1].lstrip("*")).name == UBUNTU_IMAGE_NAME and re.fullmatch(r"[a-fA-F0-9]{64}", parts[0]):
            return parts[0].lower()
    raise VMError("Could not find Ubuntu ARM64 image checksum in upstream SHA256SUMS")


def prepare_assets(root: Path, offline: bool = False) -> tuple[Path, Path]:
    assets = root / "assets"
    mkdir_private(assets)
    base = assets / "ubuntu-noble-arm64-base.qcow2"
    binary = assets / "tun2socks-linux-arm64"
    if offline:
        if not base.is_file() or not binary.is_file():
            raise VMError("Offline mode needs previously downloaded assets; run 'prepare' on macOS first")
        return base, binary
    if not base.is_file():
        sums = fetch_text(UBUNTU_SUMS_URL)
        checksum = ubuntu_sha256(sums)
        orig = assets / UBUNTU_IMAGE_NAME
        note("Downloading Ubuntu 24.04 ARM64 Cloud Image; verifying upstream SHA256 ...")
        download(UBUNTU_URL, orig, expected_sha256=checksum)
        note("Converting Ubuntu image to QCOW2 base ...")
        tmp = base.with_suffix(".tmp.qcow2")
        try:
            cmd(["qemu-img", "convert", "-O", "qcow2", str(orig), str(tmp)])
            tmp.replace(base)
        finally:
            tmp.unlink(missing_ok=True)
    if not binary.is_file():
        zipped = assets / f"tun2socks-{TUN_VERSION}-linux-arm64.zip"
        note("Downloading tun2socks pinned release and checking SHA256 ...")
        download(TUN_URL, zipped, expected_sha256=TUN_ARCHIVE_SHA256)
        with zipfile.ZipFile(zipped) as z:
            members = [x for x in z.infolist() if not x.is_dir() and Path(x.filename).name in ("tun2socks", "tun2socks-linux-arm64")]
            if len(members) != 1:
                raise VMError("tun2socks archive layout unexpected")
            with z.open(members[0]) as fin, binary.open("wb") as out:
                shutil.copyfileobj(fin, out)
        binary.chmod(0o700)
    # Reject a corrupted extracted binary if the trusted release archive is present.
    zipped = assets / f"tun2socks-{TUN_VERSION}-linux-arm64.zip"
    if zipped.exists():
        if sha256_file(zipped) != TUN_ARCHIVE_SHA256:
            raise VMError("Cached tun2socks release ZIP has an invalid checksum")
        with zipfile.ZipFile(zipped) as z:
            members = [x for x in z.infolist() if not x.is_dir() and Path(x.filename).name in ("tun2socks", "tun2socks-linux-arm64")]
            if len(members) != 1 or hashlib.sha256(z.read(members[0])).hexdigest() != sha256_file(binary):
                raise VMError("Extracted tun2socks binary does not match the pinned release")
    return base, binary


def ensure_available(cmd_name: str) -> str:
    found = shutil.which(cmd_name)
    if not found:
        raise VMError(f"Missing {cmd_name}; install with: brew install qemu xorriso")
    return found


def firmware_path(explicit: str = "") -> str:
    if explicit:
        if not Path(explicit).is_file():
            raise VMError(f"Firmware not found: {explicit}")
        return str(Path(explicit).resolve())
    guesses = [
        "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
        "/usr/local/share/qemu/edk2-aarch64-code.fd",
    ]
    brew = shutil.which("brew")
    if brew:
        result = subprocess.run([brew, "--prefix", "qemu"], capture_output=True, text=True)
        if result.returncode == 0:
            guesses.insert(0, str(Path(result.stdout.strip()) / "share/qemu/edk2-aarch64-code.fd"))
    for p in guesses:
        if Path(p).is_file():
            return p
    raise VMError("Could not find edk2-aarch64-code.fd. Set --firmware /path/to/edk2-aarch64-code.fd")


def proxy_probe(port: int) -> None:
    # SOCKS5 greeting advertising only no-auth; validates service type, not end-to-end egress.
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                raise VMError(f"127.0.0.1:{port} is not a no-auth SOCKS5 endpoint")
    except OSError as e:
        raise VMError(f"Local SOCKS5 proxy unavailable on 127.0.0.1:{port}: {e}") from e


def check_port_free(port: int) -> None:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError as e:
            raise VMError(f"SSH host port 127.0.0.1:{port} is in use: {e}") from e


def choose_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_hardware(name: str) -> dict:
    random_bytes = os.urandom(3)
    return {
        "uuid": str(uuid.uuid4()),
        "mac": "52:54:00:" + ":".join(f"{b:02x}" for b in random_bytes),
        "disk_serial": "VM" + os.urandom(8).hex().upper(),
        "machine_id": os.urandom(16).hex(),
        "smbios": {"manufacturer": "Generic", "product": "ARM64 Workstation", "version": "1.0", "serial": os.urandom(8).hex().upper()},
        "hostname": name,
    }


def share_specs(config: dict, *, check_paths: bool = True) -> list[dict]:
    shares = config.get("shares", [])
    if not isinstance(shares, list) or len(shares) > 16:
        raise VMError("shares must be an array with at most 16 entries")
    names, guests = set(), set()
    normalized = []
    for item in shares:
        if not isinstance(item, dict):
            raise VMError("Each share must be an object")
        name, host, guest = item.get("name"), item.get("host"), item.get("guest")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,24}", name):
            raise VMError("Invalid share name")
        if not isinstance(host, str) or not host.startswith("/") or any(c in host for c in ",\n\r"):
            raise VMError(f"Share {name}: host path must be absolute and contain no comma or newline")
        hostpath = Path(host).expanduser()
        if check_paths and (not hostpath.is_dir() or hostpath.is_symlink()):
            raise VMError(f"Share {name}: host must be an existing directory, not a symlink: {host}")
        # Avoid mapping the host filesystem root or broad OS/private credentials into the guest.
        real = hostpath.resolve()
        if real == Path("/") or str(real) in ("/Users", "/System", "/Library", "/private", "/etc"):
            raise VMError(f"Share {name}: broad host root is not allowed")
        if not isinstance(guest, str) or not guest.startswith("/") or any(c.isspace() for c in guest):
            raise VMError(f"Share {name}: guest path must be absolute and contain no whitespace")
        gp = Path(guest)
        if ".." in gp.parts or gp == Path("/") or not any(
            guest == prefix or guest.startswith(prefix + "/")
            for prefix in ("/mnt", "/home/vmuser", "/opt/workspaces")
        ):
            raise VMError(f"Share {name}: guest path must be below /mnt, /home/vmuser or /opt/workspaces")
        if name in names or guest in guests or any(guest.startswith(other + "/") or other.startswith(guest + "/") for other in guests):
            raise VMError("Duplicate or nested share names/guest paths")
        names.add(name)
        guests.add(guest)
        if item.get("read_only", False) is not False:
            raise VMError("Only read-write shares are currently supported")
        normalized.append({"name": name, "host": str(real), "guest": guest, "read_only": False})
    return normalized


def render_mounts(config: dict) -> str:
    shares = share_specs(config)
    lines = ["#!/bin/bash", "set -euo pipefail", "modprobe 9pnet_virtio || true", "modprobe 9p || true"]
    # Only vmproxy-owned mounts are detached. Never unmount unrelated filesystems.
    lines += ["while read -r tag target; do", "  if [[ $tag == host_* ]]; then umount -- \"$target\" || true; fi", "done < <(findmnt -rn -t 9p -o SOURCE,TARGET || true)"]
    for share in shares:
        target, tag = shlex.quote(share["guest"]), shlex.quote("host_" + share["name"])
        lines.extend([
            f"mkdir -p -- {target}",
            f"mount -t 9p -o trans=virtio,version=9p2000.L,msize=262144,access=any,rw {tag} {target}",
        ])
    return "\n".join(lines) + "\n"


def validate_config(config: dict) -> None:
    safe_name(config["name"])
    hw = config["hardware"]
    if not re.fullmatch(r"[0-9a-fA-F]{32}", hw["machine_id"]):
        raise VMError("Invalid machine_id")
    uuid.UUID(hw["uuid"])
    if not re.fullmatch(r"([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}", hw["mac"]):
        raise VMError("Invalid MAC address")
    first = int(hw["mac"].split(":")[0], 16)
    if first & 1:
        raise VMError("Multicast MAC addresses are not allowed")
    for key, val in hw["smbios"].items():
        if not isinstance(val, str) or not (1 <= len(val) <= 64) or any(x in val for x in [",", "\n", "\r"]):
            raise VMError(f"Invalid SMBIOS field {key}")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,30}", hw["disk_serial"]):
        raise VMError("Invalid disk serial")
    if config["network"].get("host_socks_host") != "127.0.0.1":
        raise VMError("Only localhost SOCKS5 forward is supported")
    if config["network"]["mode"] != "restricted-socks5":
        raise VMError("Only restricted-socks5 mode is supported (no direct fallback)")
    share_specs(config)
    p = config["network"]["host_socks_port"]
    if not isinstance(p, int) or not 1 <= p <= 65535:
        raise VMError("Invalid host_socks_port")
    bridge = config["network"].get("udp_bridge_host_port")
    if not isinstance(bridge, int) or not 1 <= bridge <= 65535:
        raise VMError("Invalid udp_bridge_host_port")
    ssh_port = config["network"]["ssh_host_port"]
    if not isinstance(ssh_port, int) or not 1 <= ssh_port <= 65535:
        raise VMError("Invalid ssh_host_port")
    if len({ssh_port, p, bridge}) != 3:
        raise VMError("SSH, SOCKS5 and UDP bridge ports must differ")


def render_guest_script(name: str, **variables: str) -> str:
    template = (HERE / "guest" / name).read_text(encoding="utf-8")
    for k, v in variables.items():
        template = template.replace("{{" + k + "}}", v)
    if "{{" in template:
        raise VMError(f"Unresolved template in {name}")
    return template


def make_seed(folder: Path, config: dict, tun_binary: Path, *, run_iso: bool = True) -> None:
    from base64 import b64encode

    validate_config(config)
    stage = folder / "seed-staging"
    if stage.exists():
        shutil.rmtree(stage)
    mkdir_private(stage)
    h = config["hardware"]
    pub = (folder / "id_ed25519.pub").read_text(encoding="ascii").strip()
    setup = render_guest_script("firstboot.sh", BINARY_SHA256=sha256_file(tun_binary), MACHINE_ID=h["machine_id"])
    route = render_guest_script("route.sh")
    service = render_guest_script("vmproxy.service")
    resolved = render_guest_script("resolved.conf")
    shim = render_guest_script("socks_shim.py")
    share_script = render_mounts(config)
    files = [
        {"path": "/usr/local/sbin/vmproxy-socks", "permissions": "0755", "encoding": "b64", "content": b64encode(shim.encode()).decode()},
        {"path": "/etc/systemd/system/vmproxy-socks.service", "permissions": "0644", "content": render_guest_script("vmproxy-socks.service")},
        {"path": "/usr/local/sbin/vmproxy-mounts", "permissions": "0755", "encoding": "b64", "content": b64encode(share_script.encode()).decode()},
        {"path": "/etc/systemd/system/vmproxy-shares.service", "permissions": "0644", "content": render_guest_script("vmproxy-shares.service")},
        {"path": "/usr/local/sbin/vmproxy-firstboot", "permissions": "0755", "encoding": "b64", "content": b64encode(setup.encode()).decode()},
        {"path": "/usr/local/sbin/vmproxy-route", "permissions": "0755", "encoding": "b64", "content": b64encode(route.encode()).decode()},
        {"path": "/etc/systemd/system/vmproxy.service", "permissions": "0644", "content": service},
        {"path": "/etc/systemd/resolved.conf.d/99-vmproxy.conf", "permissions": "0644", "content": resolved},
        {"path": "/etc/sysctl.d/99-vmproxy-ipv6.conf", "permissions": "0644", "content": "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n"},
    ]
    userdata = {
        "hostname": h["hostname"],
        "manage_etc_hosts": True,
        "ssh_pwauth": False,
        "disable_root": True,
        "users": [{"name": "vmuser", "groups": "adm,sudo", "sudo": "ALL=(ALL) NOPASSWD:ALL", "shell": "/bin/bash", "lock_passwd": True, "ssh_authorized_keys": [pub]}],
        "write_files": files,
        "runcmd": [["/bin/bash", "/usr/local/sbin/vmproxy-firstboot"]],
        "final_message": "vmproxy configured. Check: systemctl status vmproxy; ip route; resolvectl status",
    }
    # YAML 1.2 accepts JSON document bodies. This avoids a PyYAML dependency.
    (stage / "user-data").write_text("#cloud-config\n" + json.dumps(userdata, indent=2) + "\n")
    (stage / "meta-data").write_text("instance-id: " + config["cloudinit_instance"] + "\nlocal-hostname: " + h["hostname"] + "\n")
    netconfig = {
        "version": 2,
        "ethernets": {"uplink": {"match": {"macaddress": h["mac"]}, "dhcp4": True, "dhcp6": False, "accept-ra": False,
                                "dhcp4-overrides": {"use-dns": False, "use-domains": False}}},
    }
    (stage / "network-config").write_text(json.dumps(netconfig, indent=2) + "\n")
    shutil.copyfile(tun_binary, stage / "tun2socks")
    if run_iso:
        iso = folder / "seed.iso"
        tmp = folder / "seed.tmp.iso"
        cmd(["xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata", "-J", "-r", "-o", str(tmp), str(stage)])
        tmp.replace(iso)
    # staging retains a separate copy of the binary and public key; remove after ISO.
    if run_iso:
        shutil.rmtree(stage)


def init_vm(root: Path, args: argparse.Namespace) -> None:
    ensure_macos()
    for c in ("qemu-system-aarch64", "qemu-img", "xorriso", "ssh-keygen"):
        ensure_available(c)
    firmware_path(args.firmware)
    if not (1024 <= args.memory_mib <= 262144 and 1 <= args.cpus <= 32 and 12 <= args.disk_gib <= 2048):
        raise VMError("Limits: 1024..262144 MiB RAM, 1..32 CPUs, 12..2048 GiB disk")
    if not (1 <= args.ssh_port <= 65535 and 1 <= args.proxy_port <= 65535):
        raise VMError("Invalid port")
    name = safe_name(args.name)
    folder = vm_dir(root, name)
    if folder.exists():
        raise VMError(f"VM already exists: {folder}")
    base, tun = prepare_assets(root, offline=args.offline)
    shares = []
    if args.shares_file:
        shares = json.loads(Path(args.shares_file).expanduser().read_text(encoding="utf-8"))
    check_port_free(args.ssh_port)
    mkdir_private(folder)
    try:
        hardware = make_hardware(name)
        if args.mac: hardware["mac"] = args.mac.lower()
        if args.machine_uuid: hardware["uuid"] = str(uuid.UUID(args.machine_uuid))
        if args.smbios_manufacturer: hardware["smbios"]["manufacturer"] = args.smbios_manufacturer
        if args.smbios_product: hardware["smbios"]["product"] = args.smbios_product
        if args.smbios_serial: hardware["smbios"]["serial"] = args.smbios_serial
        config = {
            "shares": shares,
            "version": 2, "name": name, "architecture": "aarch64", "os": "ubuntu-24.04",
            "resources": {"memory_mib": args.memory_mib, "cpus": args.cpus, "disk_gib": args.disk_gib},
            "hardware": hardware,
            "network": {"mode": "restricted-socks5", "host_socks_host": "127.0.0.1", "host_socks_port": args.proxy_port,
                        "guest_socks_host": PROXY_GUEST_IP, "guest_socks_port": PROXY_GUEST_PORT, "ssh_host_port": args.ssh_port,
                        "udp_bridge_host_port": args.udp_bridge_port or choose_free_port()},
            "cloudinit_instance": str(uuid.uuid4()),
            "firmware": str(Path(args.firmware).expanduser().resolve()) if args.firmware else "auto",
        }
        validate_config(config)
        write_private(folder / "config.json", json.dumps(config, indent=2, ensure_ascii=False) + "\n")
        cmd(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(folder / "id_ed25519")])
        (folder / "id_ed25519").chmod(0o600)
        cmd(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(folder / "disk.qcow2"), f"{args.disk_gib}G"])
        make_seed(folder, config, tun)
    except Exception:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    note(f"Created VM '{name}' at {folder}\nStart: python3 vmctl.py --root {root} start {name}")


def qmp_path(root: Path, name: str) -> Path:
    # macOS unix socket paths have a restrictive length limit; /tmp is short.
    sig = hashlib.sha256((str(root.resolve()) + ":" + name).encode()).hexdigest()[:24]
    return Path("/tmp") / f"mvp-{sig}.qmp"


def qmp_exec(sockpath: Path, command: str) -> dict:
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2)
        s.connect(str(sockpath))
        stream = s.makefile("rwb", buffering=0)
        def line() -> dict:
            raw = stream.readline()
            return json.loads(raw) if raw else {}
        greet = line()
        if "QMP" not in greet:
            raise VMError("Unexpected QMP response")
        s.sendall(b'{"execute":"qmp_capabilities"}\n')
        while "return" not in line():
            pass
        s.sendall((json.dumps({"execute": command}) + "\n").encode())
        while True:
            result = line()
            if not result:
                raise VMError("QMP disconnected")
            if "return" in result or "error" in result:
                return result


def alive_qmp(sockpath: Path) -> bool:
    if not sockpath.exists():
        return False
    try:
        return "return" in qmp_exec(sockpath, "query-status")
    except (OSError, VMError, ValueError, TimeoutError):
        return False


def qemu_argv(root: Path, name: str, config: dict, *, firmware: str) -> list[str]:
    validate_config(config)
    folder = vm_dir(root, name)
    nw, hw, res = config["network"], config["hardware"], config["resources"]
    smbios = hw["smbios"]
    smb = "type=1," + ",".join(f"{k}={smbios[k]}" for k in ("manufacturer", "product", "version", "serial")) + ",uuid=" + hw["uuid"]
    net = (
        "user,id=n0,restrict=on,ipv6=off,"
        f"guestfwd=tcp:{PROXY_GUEST_IP}:{PROXY_GUEST_PORT}-tcp:127.0.0.1:{nw['host_socks_port']},"
        f"guestfwd=tcp:{UDP_BRIDGE_GUEST_IP}:{UDP_BRIDGE_GUEST_PORT}-tcp:127.0.0.1:{nw['udp_bridge_host_port']},"
        f"hostfwd=tcp:127.0.0.1:{nw['ssh_host_port']}-:22"
    )
    shares = share_specs(config)
    virtfs = []
    for share in shares:
        fsid = "fs_" + share["name"]
        virtfs.extend(["-fsdev", f"local,id={fsid},path={share['host']},security_model=none,multidevs=remap",
                       "-device", f"virtio-9p-pci,fsdev={fsid},mount_tag=host_{share['name']}"])
    return [
        "qemu-system-aarch64", "-name", f"mac-vmproxy-{name}",
        "-machine", "virt,highmem=on", "-accel", "hvf", "-cpu", "host",
        "-smp", str(res["cpus"]), "-m", str(res["memory_mib"]),
        "-uuid", hw["uuid"], "-smbios", smb,
        "-bios", firmware,
        "-drive", f"file={folder / 'disk.qcow2'},format=qcow2,if=none,id=d0,cache=writeback",
        "-device", f"virtio-blk-pci,drive=d0,bootindex=1,serial={hw['disk_serial']}",
        "-device", "virtio-scsi-pci,id=scsi0",
        "-drive", f"file={folder / 'seed.iso'},format=raw,media=cdrom,if=none,id=seed,readonly=on",
        "-device", "scsi-cd,drive=seed,bus=scsi0.0",
        "-netdev", net, "-device", f"virtio-net-pci,netdev=n0,mac={hw['mac']}",
        *virtfs,
        "-display", "none", "-monitor", "none", "-serial", f"file:{folder / 'serial.log'}",
        "-qmp", f"unix:{qmp_path(root, name)},server=on,wait=off",
    ]


def bridge_pid_path(folder: Path) -> Path:
    return folder / "udp-bridge.pid"


def bridge_pid(folder: Path) -> int | None:
    try:
        return int(bridge_pid_path(folder).read_text().strip())
    except (OSError, ValueError):
        return None


def bridge_owned(pid: int, port: int) -> bool:
    if pid <= 0 or port <= 0:
        return False
    proc = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True)
    if proc.returncode:
        return False
    line = proc.stdout.strip()
    return "udp_bridge.py" in line and f"--listen-port {port}" in line


def kill_bridge(folder: Path) -> None:
    pid = bridge_pid(folder)
    try:
        cfg = json.loads((folder / "config.json").read_text())
        port = cfg["network"]["udp_bridge_host_port"]
    except (OSError, ValueError, KeyError):
        port = 0
    if pid and bridge_owned(pid, port):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    bridge_pid_path(folder).unlink(missing_ok=True)


def start_bridge(folder: Path, nw: dict) -> None:
    port = nw["udp_bridge_host_port"]
    pid = bridge_pid(folder)
    if pid:
        if bridge_owned(pid, port):
            raise VMError(f"UDP bridge already running (PID {pid}); stop the VM first")
        bridge_pid_path(folder).unlink(missing_ok=True)
    check_port_free(port)
    from udp_bridge import udp_associate
    ctrl, udp = udp_associate(nw["host_socks_port"])
    ctrl.close()
    udp.close()
    with (folder / "udp-bridge.log").open("ab") as log:
        proc = subprocess.Popen([sys.executable, str(HERE / "udp_bridge.py"),
                                 "--listen-port", str(port), "--proxy-port", str(nw["host_socks_port"])],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    write_private(bridge_pid_path(folder), str(proc.pid) + "\n")
    for _ in range(30):
        if proc.poll() is not None:
            bridge_pid_path(folder).unlink(missing_ok=True)
            raise VMError(f"UDP bridge failed; see {folder / 'udp-bridge.log'}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    kill_bridge(folder)
    raise VMError("UDP bridge did not become ready")


def start_vm(root: Path, name: str, dry_run: bool = False, *, skip_proxy_probe: bool = False) -> None:
    folder, config = read_config(root, name)
    firmware = firmware_path("" if config["firmware"] == "auto" else config["firmware"])
    argv = qemu_argv(root, name, config, firmware=firmware)
    if dry_run:
        note(" ".join(__import__("shlex").quote(s) for s in argv))
        return
    ensure_macos()
    ensure_available("qemu-system-aarch64")
    path = qmp_path(root, name)
    if alive_qmp(path):
        raise VMError(f"VM '{name}' already running")
    if path.exists():
        path.unlink()
    if not skip_proxy_probe:
        proxy_probe(config["network"]["host_socks_port"])
    check_port_free(config["network"]["ssh_host_port"])
    start_bridge(folder, config["network"])
    try:
        with (folder / "qemu.log").open("ab") as log:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    except BaseException:
        kill_bridge(folder)
        raise
    write_private(folder / "pid", str(child.pid) + "\n")
    for _ in range(30):
        if child.poll() is not None:
            kill_bridge(folder)
            raise VMError(f"QEMU exited with {child.returncode}; see {folder / 'qemu.log'}")
        if alive_qmp(path):
            note(f"Started {name}: QEMU PID {child.pid}; ssh on 127.0.0.1:{config['network']['ssh_host_port']}")
            note(f"Guest setup runs on first boot. Logs: {folder / 'serial.log'}")
            return
        time.sleep(0.2)
    kill_bridge(folder)
    raise VMError(f"QEMU launched but QMP not ready; inspect {folder / 'qemu.log'}")


def stop_vm(root: Path, name: str) -> None:
    folder = vm_dir(root, name)
    path = qmp_path(root, name)
    if not alive_qmp(path):
        kill_bridge(folder)
        note(f"VM {name} not running")
        return
    result = qmp_exec(path, "system_powerdown")
    if "error" in result:
        raise VMError(f"QMP powerdown error: {result['error']}")
    note("Sent ACPI powerdown; waiting for VM shutdown...")
    for _ in range(100):
        if not alive_qmp(path):
            kill_bridge(folder)
            note("VM stopped; UDP bridge stopped")
            return
        time.sleep(0.2)
    note("VM still running. UDP bridge retained; check status and run stop again.")


def status_vm(root: Path, name: str) -> None:
    folder, config = read_config(root, name)
    running = alive_qmp(qmp_path(root, name))
    note(json.dumps({"name": name, "running": running, "udp_bridge_pid": bridge_pid(folder),
                     "shares": share_specs(config), "ssh_port": config["network"]["ssh_host_port"],
                     "proxy": f"127.0.0.1:{config['network']['host_socks_port']}", "path": str(folder)}, indent=2))


def ssh_vm(root: Path, name: str, args: list[str]) -> None:
    folder, config = read_config(root, name)
    port = config["network"]["ssh_host_port"]
    known_hosts = folder / "known_hosts"
    argv = ["ssh", "-i", str(folder / "id_ed25519"), "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "StrictHostKeyChecking=accept-new", "-p", str(port), "vmuser@127.0.0.1", *args]
    raise SystemExit(subprocess.call(argv))


def sync_shares(root: Path, name: str) -> None:
    folder, config = read_config(root, name)
    validate_config(config)
    if not alive_qmp(qmp_path(root, name)):
        raise VMError("VM must be running; restart after changing shares so QEMU attaches exports")
    script = render_mounts(config)
    port = config["network"]["ssh_host_port"]
    ssh = ["ssh", "-i", str(folder / "id_ed25519"), "-o", f"UserKnownHostsFile={folder / 'known_hosts'}",
           "-o", "StrictHostKeyChecking=accept-new", "-p", str(port), "vmuser@127.0.0.1"]
    subprocess.run([*ssh, "sudo tee /usr/local/sbin/vmproxy-mounts >/dev/null && "
                           "sudo chmod 755 /usr/local/sbin/vmproxy-mounts && "
                           "sudo systemctl restart vmproxy-shares.service"],
                   input=script, text=True, check=True)
    note("Shares sync done. Verify mounts with: findmnt -t 9p")


def doctor(proxy_port: int, firmware: str) -> None:
    ensure_macos()
    for c in ("qemu-system-aarch64", "qemu-img", "xorriso", "ssh-keygen", "ssh"):
        note(f"{c}: {ensure_available(c)}")
    note(f"UEFI: {firmware_path(firmware)}")
    proxy_probe(proxy_port)
    from udp_bridge import udp_associate
    ctrl, udp = udp_associate(proxy_port)
    ctrl.close()
    udp.close()
    note(f"SOCKS5 TCP + UDP ASSOCIATE OK on 127.0.0.1:{proxy_port}")
    note("Note: a successful handshake does not verify upstream routing or IP address.")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="macOS QEMU/HVF Linux ARM64 VM with restricted SOCKS5 networking")
    p.add_argument("--root", type=Path, default=DEFAULT_ROOT, help=f"VM storage root (default {DEFAULT_ROOT})")
    sub = p.add_subparsers(dest="action", required=True)
    d = sub.add_parser("doctor", help="Check local dependencies and SOCKS5")
    d.add_argument("--proxy-port", type=int, default=7891)
    d.add_argument("--firmware", default="")
    b = sub.add_parser("prepare", help="Download and verify guest images and tun2socks")
    i = sub.add_parser("init", help="Create VM disk, SSH key, config and cloud-init ISO")
    i.add_argument("name")
    i.add_argument("--cpus", type=int, default=4)
    i.add_argument("--memory-mib", type=int, default=4096)
    i.add_argument("--disk-gib", type=int, default=32)
    i.add_argument("--proxy-port", type=int, default=7891)
    i.add_argument("--ssh-port", type=int, default=2222)
    i.add_argument("--udp-bridge-port", type=int, default=0, help="Local TCP bridge port; 0 chooses a free port")
    i.add_argument("--shares-file", default="", help="JSON array of {name,host,guest} read-write directory shares")
    i.add_argument("--firmware", default="")
    i.add_argument("--offline", action="store_true", help="Use previously downloaded assets")
    i.add_argument("--mac", default="", help="Custom guest MAC (default per-VM random)")
    i.add_argument("--machine-uuid", default="", help="Custom SMBIOS UUID (default per-VM random)")
    i.add_argument("--smbios-manufacturer", default="", help="SMBIOS manufacturer, max 64 chars, no commas")
    i.add_argument("--smbios-product", default="", help="SMBIOS product, max 64 chars, no commas")
    i.add_argument("--smbios-serial", default="", help="SMBIOS serial, max 64 chars, no commas")
    sync = sub.add_parser("sync-shares", help="Update guest 9P mount script after changing config and rebooting")
    sync.add_argument("name")
    s = sub.add_parser("start", help="Start VM and require local SOCKS5")
    s.add_argument("name")
    s.add_argument("--dry-run", action="store_true")
    t = sub.add_parser("stop", help="ACPI graceful shutdown")
    t.add_argument("name")
    st = sub.add_parser("status", help="QMP status")
    st.add_argument("name")
    ssh = sub.add_parser("ssh", help="SSH to guest")
    ssh.add_argument("name")
    ssh.add_argument("ssh_args", nargs=argparse.REMAINDER)
    return p


def main() -> None:
    # Protect VM config, SSH material and local QMP socket from other macOS users.
    os.umask(0o077)
    p = parser()
    opts = p.parse_args()
    root = opts.root.expanduser().resolve()
    try:
        if opts.action == "doctor": doctor(opts.proxy_port, opts.firmware)
        elif opts.action == "prepare":
            ensure_macos()
            ensure_available("qemu-img")
            base, tun = prepare_assets(root)
            note(f"Assets ready: {base}, {tun}")
        elif opts.action == "init": init_vm(root, opts)
        elif opts.action == "start": start_vm(root, opts.name, opts.dry_run)
        elif opts.action == "stop": stop_vm(root, opts.name)
        elif opts.action == "status": status_vm(root, opts.name)
        elif opts.action == "ssh": ssh_vm(root, opts.name, opts.ssh_args)
        elif opts.action == "sync-shares": sync_shares(root, opts.name)
    except (VMError, subprocess.CalledProcessError, OSError, KeyError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
