#!/usr/bin/env python3
"""Guest-local SOCKS5 shim: CONNECT via QEMU TCP forward; UDP via framed TCP bridge.

Only listens on the guest loopback interface. No direct egress fallback.
"""
import argparse
import select
import socket
import socketserver
import struct
import threading

UPSTREAM_HOST = '10.0.2.100'
UPSTREAM_PORT = 1080
UDP_BRIDGE_HOST = '10.0.2.101'
UDP_BRIDGE_PORT = 1081


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError('socket closed')
        out.extend(chunk)
    return bytes(out)


def read_addr(sock, atyp):
    if atyp == 1:
        return exact(sock, 4)
    if atyp == 4:
        return exact(sock, 16)
    if atyp == 3:
        n = exact(sock, 1)[0]
        return bytes([n]) + exact(sock, n)
    raise ValueError('invalid SOCKS address type')


def pump(a, b):
    sockets = (a, b)
    while True:
        ready, _, _ = select.select(sockets, [], [], 30)
        for sock in ready:
            data = sock.recv(65536)
            dst = b if sock is a else a
            if not data:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            dst.sendall(data)


def connect_upstream(request, client):
    with socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), 10) as upstream:
        upstream.sendall(b'\x05\x01\x00')
        if exact(upstream, 2) != b'\x05\x00':
            raise ConnectionError('upstream SOCKS5 no-auth denied')
        upstream.sendall(request)
        hdr = exact(upstream, 4)
        if hdr[0] != 5:
            raise ConnectionError('invalid upstream SOCKS reply')
        result = hdr + read_addr(upstream, hdr[3]) + exact(upstream, 2)
        client.sendall(result)
        if hdr[1] != 0:
            return
        pump(client, upstream)


def udp_associate(control):
    # Control TCP session lifetime bounds the UDP association.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.create_connection(
        (UDP_BRIDGE_HOST, UDP_BRIDGE_PORT), 10
    ) as tunnel:
        udp.bind(('127.0.0.1', 0))
        port = udp.getsockname()[1]
        control.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', port))
        stash = bytearray()
        client = None
        while True:
            readable, _, _ = select.select([control, udp, tunnel], [], [], 60)
            for s in readable:
                if s is control:
                    # SOCKS5 UDP ASSOCIATE control closes when the client is finished.
                    if not control.recv(4096):
                        return
                elif s is udp:
                    data, origin = udp.recvfrom(65535)
                    if origin[0] != '127.0.0.1' or len(data) < 4 or data[:3] != b'\x00\x00\x00':
                        continue
                    if len(data) > 65535:
                        continue
                    client = origin
                    tunnel.sendall(struct.pack('!H', len(data)) + data)
                else:
                    chunk = tunnel.recv(65536)
                    if not chunk:
                        return
                    stash.extend(chunk)
                    while len(stash) >= 2:
                        n = struct.unpack('!H', stash[:2])[0]
                        if n == 0:
                            raise ConnectionError('empty tunnel packet')
                        if len(stash) < 2 + n:
                            break
                        payload = bytes(stash[2:2+n])
                        del stash[:2+n]
                        if client:
                            udp.sendto(payload, client)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(20)
        try:
            if exact(sock, 1) != b'\x05':
                return
            methods = exact(sock, 1)[0]
            offered = exact(sock, methods)
            if 0 not in offered:
                sock.sendall(b'\x05\xff')
                return
            sock.sendall(b'\x05\x00')
            hdr = exact(sock, 4)
            if hdr[0] != 5 or hdr[2] != 0:
                return
            body = read_addr(sock, hdr[3]) + exact(sock, 2)
            if hdr[1] == 1:
                connect_upstream(hdr + body, sock)
            elif hdr[1] == 3:
                udp_associate(sock)
            else:
                sock.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)
        except (OSError, ValueError, ConnectionError):
            try:
                sock.sendall(b'\x05\x01\x00\x01' + b'\x00' * 6)
            except OSError:
                pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--listen', type=int, default=1081)
    args = p.parse_args()
    with Server(('127.0.0.1', args.listen), Handler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
