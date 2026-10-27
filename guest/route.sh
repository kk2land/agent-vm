#!/bin/sh
# Guest boot script; QEMU restrict=on is the ultimate fail-closed boundary.
set -eu
ip tuntap add mode tun dev tun0 2>/dev/null || ip link show tun0 >/dev/null
ip addr replace 198.18.0.1/15 dev tun0
ip link set dev tun0 mtu 1400 up
# 10.0.2.100 is on eth0's connected subnet, so SOCKS connections cannot loop
# back through tun0. Clear competing default routes to make behavior predictable.
ip -4 route replace default dev tun0 metric 1
# Primary DHCP route may reappear with higher metric; QEMU still blocks direct egress.
