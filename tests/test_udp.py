"""Host-side UDP-over-TCP and guest SOCKS5 UDP end-to-end loopback tests."""
import importlib.util
import socket
import socketserver
import struct
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import udp_bridge

spec = importlib.util.spec_from_file_location('socks_shim', ROOT / 'guest' / 'socks_shim.py')
shim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shim)


def recvn(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('closed')
        data.extend(chunk)
    return bytes(data)


class FakeSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(4)
        if recvn(sock, 3) != b'\x05\x01\x00':
            return
        sock.sendall(b'\x05\x00')
        request = recvn(sock, 10)
        if request[:4] != b'\x05\x03\x00\x01':
            return
        p = self.server.udp_port
        sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00' + struct.pack('!H', p))
        try:
            while sock.recv(1):
                pass
        except socket.timeout:
            pass


class FakeSocks(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpTests(unittest.TestCase):
    def test_reject_malformed_datagrams(self):
        self.assertFalse(udp_bridge.valid_udp_packet(b'hello'))
        self.assertFalse(udp_bridge.valid_udp_packet(b'\x00\x00\x01\x01' + b'\x00' * 7))
        self.assertTrue(udp_bridge.valid_udp_packet(b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35hello'))

    def test_udp_end_to_end_via_tcp_and_socks5(self):
        upstream_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_udp.bind(('127.0.0.1', 0))
        upstream_udp.settimeout(0.3)
        done = threading.Event()
        def udp_echo():
            while not done.is_set():
                try:
                    data, origin = upstream_udp.recvfrom(65535)
                    upstream_udp.sendto(data, origin)
                except socket.timeout:
                    continue
                except OSError:
                    break
        echo_thread = threading.Thread(target=udp_echo, daemon=True)
        echo_thread.start()
        try:
            with FakeSocks(('127.0.0.1', 0), FakeSocksHandler) as upstream:
                upstream.udp_port = upstream_udp.getsockname()[1]
                upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
                upstream_thread.start()
                with udp_bridge.Server(('127.0.0.1', 0), udp_bridge.Handler) as bridge:
                    bridge.proxy_port = upstream.server_address[1]
                    bridge_thread = threading.Thread(target=bridge.serve_forever, daemon=True)
                    bridge_thread.start()
                    old = shim.UDP_BRIDGE_HOST, shim.UDP_BRIDGE_PORT
                    shim.UDP_BRIDGE_HOST, shim.UDP_BRIDGE_PORT = '127.0.0.1', bridge.server_address[1]
                    try:
                        with shim.Server(('127.0.0.1', 0), shim.Handler) as guest:
                            guest_thread = threading.Thread(target=guest.serve_forever, daemon=True)
                            guest_thread.start()
                            with socket.create_connection(guest.server_address, timeout=4) as client:
                                client.settimeout(4)
                                client.sendall(b'\x05\x01\x00')
                                self.assertEqual(recvn(client, 2), b'\x05\x00')
                                client.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                                answer = recvn(client, 10)
                                self.assertEqual(answer[:4], b'\x05\x00\x00\x01')
                                listen_port = struct.unpack('!H', answer[-2:])[0]
                                datagram = b'\x00\x00\x00\x01\x01\x01\x01\x01\x00\x35UDP-test'
                                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                                    sender.settimeout(4)
                                    sender.sendto(datagram, ('127.0.0.1', listen_port))
                                    reply, _ = sender.recvfrom(65535)
                                    self.assertEqual(reply, datagram)
                            guest.shutdown()
                    finally:
                        shim.UDP_BRIDGE_HOST, shim.UDP_BRIDGE_PORT = old
                    bridge.shutdown()
                upstream.shutdown()
        finally:
            done.set()
            upstream_udp.close()
            echo_thread.join(timeout=2)

    def test_denies_proxy_udp_associate_nonlocal_relay(self):
        class NonLocalHandler(FakeSocksHandler):
            def handle(self):
                sock = self.request
                recvn(sock, 3)
                sock.sendall(b'\x05\x00')
                recvn(sock, 10)
                sock.sendall(b'\x05\x00\x00\x01\x08\x08\x08\x08\x00\x35')
        with FakeSocks(('127.0.0.1', 0), NonLocalHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            with self.assertRaises(ConnectionError):
                udp_bridge.udp_associate(server.server_address[1])
            server.shutdown()


if __name__ == '__main__':
    unittest.main()
