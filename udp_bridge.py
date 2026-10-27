#!/usr/bin/env python3
"""Host UDP-over-TCP bridge into a loopback SOCKS5 UDP ASSOCIATE endpoint.

QEMU guestfwd TCP is the only routable path out of a restricted guest. The bridge
carries SOCKS5 UDP datagrams as length-prefixed frames over that TCP connection.
The host only sends UDP to a SOCKS5 UDP relay on 127.0.0.1/::1; never direct.
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import select
import socket
import socketserver
import struct

LOG = logging.getLogger('udp-bridge')


def recv_exact(sock: socket.socket, n: int) -> bytes:
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n - len(result))
        if not chunk:
            raise ConnectionError('SOCKS5 proxy closed the connection')
        result.extend(chunk)
    return bytes(result)


def udp_associate(proxy_port: int) -> tuple[socket.socket, socket.socket]:
    """Return control TCP and connected UDP socket. Fail closed for nonlocal relays."""
    ctrl = socket.create_connection(('127.0.0.1', proxy_port), 5)
    try:
        ctrl.settimeout(5)
        ctrl.sendall(b'\x05\x01\x00')
        if recv_exact(ctrl, 2) != b'\x05\x00':
            raise ConnectionError('SOCKS5 proxy does not offer no-auth access')
        ctrl.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        hdr = recv_exact(ctrl, 4)
        if hdr[:3] != b'\x05\x00\x00':
            raise ConnectionError(f'SOCKS5 UDP ASSOCIATE rejected: {hdr.hex()}')
        atyp = hdr[3]
        if atyp == 1:
            ip = ipaddress.ip_address(recv_exact(ctrl, 4))
        elif atyp == 4:
            ip = ipaddress.ip_address(recv_exact(ctrl, 16))
        elif atyp == 3:
            length = recv_exact(ctrl, 1)[0]
            domain = recv_exact(ctrl, length).decode('ascii', errors='replace')
            if domain.lower() not in ('localhost',):
                raise ConnectionError(f'nonlocal UDP relay rejected: {domain}')
            ip = ipaddress.ip_address('127.0.0.1')
        else:
            raise ConnectionError(f'invalid UDP relay ATYP: {atyp}')
        relay_port = struct.unpack('!H', recv_exact(ctrl, 2))[0]
        if relay_port == 0 or not (ip.is_loopback or ip.is_unspecified):
            raise ConnectionError(f'nonlocal SOCKS5 UDP relay rejected: {ip}:{relay_port}')
        if ip.is_unspecified:
            ip = ipaddress.ip_address('::1' if ip.version == 6 else '127.0.0.1')
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        udp = socket.socket(family, socket.SOCK_DGRAM)
        try:
            udp.connect((str(ip), relay_port))
        except BaseException:
            udp.close()
            raise
        ctrl.settimeout(None)
        return ctrl, udp
    except BaseException:
        ctrl.close()
        raise


def valid_udp_packet(data: bytes) -> bool:
    """RFC1928 UDP header: RSV(2) FRAG(1)=0 ATYP(1), addr/port and body."""
    if len(data) < 10 or data[:3] != b'\x00\x00\x00':
        return False
    atyp = data[3]
    if atyp == 1:
        return len(data) >= 10
    if atyp == 4:
        return len(data) >= 22
    if atyp == 3:
        return len(data) >= 7 + data[4]
    return False


def relay(tcp: socket.socket, proxy_port: int) -> None:
    ctrl, udp = udp_associate(proxy_port)
    with ctrl, udp:
        frames = bytearray()
        tcp.settimeout(None)
        while True:
            ready, _, _ = select.select([tcp, udp, ctrl], [], [], 60)
            for s in ready:
                if s is ctrl:
                    # SOCKS server ended UDP association; never fall back to direct.
                    if not ctrl.recv(1):
                        return
                elif s is tcp:
                    packet = tcp.recv(65536)
                    if not packet:
                        return
                    frames.extend(packet)
                    while len(frames) >= 2:
                        length = struct.unpack('!H', frames[:2])[0]
                        if not length:
                            raise ConnectionError('zero-sized UDP frame')
                        if len(frames) < length + 2:
                            break
                        data = bytes(frames[2:length + 2])
                        del frames[:length + 2]
                        if valid_udp_packet(data):
                            udp.send(data)
                else:
                    data = udp.recv(65535)
                    if data and valid_udp_packet(data):
                        tcp.sendall(struct.pack('!H', len(data)) + data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            relay(self.request, self.server.proxy_port)
        except (OSError, ConnectionError, ValueError) as exc:
            LOG.warning('udp bridge session ended: %s', exc)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


def serve(listen_port: int, proxy_port: int) -> None:
    # Eagerly check the upstream supports UDP. There is no alternate route.
    control, udp = udp_associate(proxy_port)
    control.close()
    udp.close()
    with Server(('127.0.0.1', listen_port), Handler) as server:
        server.proxy_port = proxy_port
        LOG.info('host UDP bridge listening on 127.0.0.1:%s; SOCKS5 %s', listen_port, proxy_port)
        server.serve_forever(poll_interval=0.2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen-port', type=int, required=True)
    parser.add_argument('--proxy-port', type=int, required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    serve(args.listen_port, args.proxy_port)
