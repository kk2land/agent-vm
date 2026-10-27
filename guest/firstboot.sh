#!/bin/bash
set -euo pipefail
# Called from cloud-init final stage, with a NoCloud ISO attached as virtual CD.
mkdir -p /mnt/vmproxy-seed
if ! mountpoint -q /mnt/vmproxy-seed; then
  for dev in /dev/disk/by-label/cidata /dev/disk/by-label/CIDATA /dev/sr0 /dev/sr1; do
    if [[ -e "$dev" ]] && mount -o ro "$dev" /mnt/vmproxy-seed 2>/dev/null; then break; fi
  done
fi
if [[ ! -f /mnt/vmproxy-seed/tun2socks ]]; then
  echo 'vmproxy: tun2socks missing from cloud-init seed media' >&2
  exit 1
fi
printf '%s  %s\n' '{{BINARY_SHA256}}' /mnt/vmproxy-seed/tun2socks | sha256sum -c -
install -m 0755 /mnt/vmproxy-seed/tun2socks /usr/local/bin/tun2socks
# Persist a random per-VM identity, never copy the macOS host machine identity.
printf '%s\n' '{{MACHINE_ID}}' > /etc/machine-id
if [[ -e /var/lib/dbus/machine-id && ! -L /var/lib/dbus/machine-id ]]; then
  printf '%s\n' '{{MACHINE_ID}}' > /var/lib/dbus/machine-id
fi
systemctl daemon-reload
sysctl -p /etc/sysctl.d/99-vmproxy-ipv6.conf || true
systemctl restart systemd-resolved
systemctl enable --now vmproxy-socks.service
systemctl enable --now vmproxy.service
systemctl enable --now vmproxy-shares.service
printf 'vmproxy: first boot configuration complete\n'
