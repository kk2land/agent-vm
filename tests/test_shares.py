import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vmctl


class SharesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)
        self.shared = self.path / 'testshare'
        self.shared.mkdir()
        self.config = {
            'version': 2,
            'name': 'dev1',
            'architecture': 'aarch64',
            'resources': {'memory_mib': 4096, 'cpus': 4, 'disk_gib': 32},
            'hardware': vmctl.make_hardware('dev1'),
            'network': {'mode': 'restricted-socks5', 'host_socks_host': '127.0.0.1',
                        'host_socks_port': 7891, 'udp_bridge_host_port': 12789, 'ssh_host_port': 2222},
            'shares': [{'name': 'projects', 'host': str(self.shared), 'guest': '/home/vmuser/projects'}],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_write_fsdev_and_guest_mount(self):
        argv = vmctl.qemu_argv(self.path, 'dev1', self.config, firmware='/tmp/dummy.fd')
        cmd = ' '.join(argv)
        self.assertIn('path=' + str(self.shared), cmd)
        self.assertIn('virtio-9p-pci,fsdev=fs_projects,mount_tag=host_projects', cmd)
        self.assertIn('security_model=none', cmd)
        mounts = vmctl.render_mounts(self.config)
        self.assertIn('mount -t 9p', mounts)
        self.assertIn('/home/vmuser/projects', mounts)
        self.assertIn('host_projects', mounts)

    def test_refuse_unsafe_host_guest_paths(self):
        for host, guest in [(str(self.shared), '/etc'), ('/', '/mnt/test'), (str(self.shared), '/mnt/../etc')]:
            self.config['shares'][0]['host'] = host
            self.config['shares'][0]['guest'] = guest
            with self.assertRaises(vmctl.VMError):
                vmctl.validate_config(self.config)

    def test_reject_missing_source_or_duplicated_targets(self):
        self.config['shares'][0]['host'] = str(self.path / 'missing')
        with self.assertRaises(vmctl.VMError):
            vmctl.validate_config(self.config)
        self.config['shares'][0]['host'] = str(self.shared)
        self.config['shares'].append({'name': 'other', 'host': str(self.shared), 'guest': '/home/vmuser/projects'})
        with self.assertRaises(vmctl.VMError):
            vmctl.validate_config(self.config)


if __name__ == '__main__':
    unittest.main()
