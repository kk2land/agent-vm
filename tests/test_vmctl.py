import json
import os
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vmctl


class VmctlTests(unittest.TestCase):
    def setUp(self):
        self.ctx = tempfile.TemporaryDirectory()
        self.root = Path(self.ctx.name)
        self.name = "dev1"
        self.folder = vmctl.vm_dir(self.root, self.name)
        vmctl.mkdir_private(self.folder)
        self.config = {
            "version": 1, "name": self.name, "architecture": "aarch64", "os": "ubuntu-24.04",
            "resources": {"cpus": 4, "memory_mib": 4096, "disk_gib": 32},
            "hardware": vmctl.make_hardware(self.name),
            "network": {"mode": "restricted-socks5", "host_socks_host": "127.0.0.1",
                        "host_socks_port": 7891, "ssh_host_port": 2222, "udp_bridge_host_port": 12081},
            "cloudinit_instance": "vmtest-1",
            "firmware": "auto",
        }

    def tearDown(self):
        self.ctx.cleanup()

    def test_hardware_identity_is_independent(self):
        a = vmctl.make_hardware("a")
        b = vmctl.make_hardware("b")
        self.assertNotEqual(a["uuid"], b["uuid"])
        self.assertNotEqual(a["mac"], b["mac"])
        self.assertNotEqual(a["machine_id"], b["machine_id"])
        vmctl.validate_config(self.config)

    def test_reject_invalid_vm_names(self):
        for invalid in ("../other", "", "A", "foo/bar", "a" * 60, "hello world"):
            with self.assertRaises(vmctl.VMError):
                vmctl.safe_name(invalid)

    def test_qemu_uses_restricted_network_with_tcp_and_udp_bridge(self):
        argv = vmctl.qemu_argv(self.root, self.name, self.config, firmware="/tmp/edk2.fd")
        self.assertIn("hvf", argv)
        net = argv[argv.index("-netdev") + 1]
        self.assertIn("restrict=on", net)
        self.assertIn("ipv6=off", net)
        self.assertIn("guestfwd=tcp:10.0.2.100:1080-tcp:127.0.0.1:7891", net)
        self.assertIn("hostfwd=tcp:127.0.0.1:2222-:22", net)
        self.assertNotIn("restrict=off", " ".join(argv))
        self.assertEqual(2, sum(x.startswith("guestfwd=") for x in net.split(",")))
        self.assertIn("guestfwd=tcp:10.0.2.101:1081-tcp:127.0.0.1:12081", net)
        self.assertIn("-smbios", argv)
        self.assertIn(self.config["hardware"]["uuid"], argv)

    def test_cloud_init_has_proxy_config_and_no_password(self):
        (self.folder / "id_ed25519.pub").write_text("ssh-ed25519 AAAATEST example@local\n")
        binary = self.folder / "tun2socks"
        binary.write_bytes(b"dummy test ELF")
        vmctl.make_seed(self.folder, self.config, binary, run_iso=False)
        stage = self.folder / "seed-staging"
        userdata = (stage / "user-data").read_text()
        self.assertTrue(userdata.startswith("#cloud-config\n"))
        body = json.loads(userdata.split("\n", 1)[1])
        self.assertFalse(body["ssh_pwauth"])
        self.assertEqual("vmuser", body["users"][0]["name"])
        self.assertTrue(body["users"][0]["lock_passwd"])
        contents = "\n".join(x.get("content", "") for x in body["write_files"])
        self.assertIn("DNSOverTLS=yes", contents)
        netconfig = json.loads((stage / "network-config").read_text())
        self.assertFalse(netconfig["ethernets"]["uplink"]["dhcp4-overrides"]["use-dns"])
        self.assertEqual(self.config["hardware"]["mac"], netconfig["ethernets"]["uplink"]["match"]["macaddress"])

    def test_insecure_fallback_not_allowed(self):
        self.config["network"]["mode"] = "direct"
        with self.assertRaises(vmctl.VMError):
            vmctl.validate_config(self.config)

    def test_manifest_parse(self):
        self.assertEqual("a" * 64, vmctl.ubuntu_sha256("a" * 64 + " *noble-server-cloudimg-arm64.img\n"))
        with self.assertRaises(vmctl.VMError):
            vmctl.ubuntu_sha256("invalid")

    def test_smbios_rejects_comma_or_newline(self):
        self.config["hardware"]["smbios"]["product"] = "bad,product"
        with self.assertRaises(vmctl.VMError):
            vmctl.validate_config(self.config)

    def test_guest_proxy_route_persists_outage_behavior(self):
        route = (vmctl.HERE / "guest" / "route.sh").read_text()
        self.assertIn("dev tun0", route)
        self.assertIn("default dev tun0", route)
        svc = (vmctl.HERE / "guest" / "vmproxy.service").read_text()
        self.assertIn("socks5://127.0.0.1:1081", svc)
        self.assertIn("vmproxy-socks.service", svc)
        self.assertIn("Restart=always", svc)

if __name__ == "__main__":
    unittest.main()
