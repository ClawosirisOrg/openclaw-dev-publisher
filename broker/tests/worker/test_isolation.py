"""Synthetic namespace metadata; no container start or host namespace mutation."""
import io
import unittest
from unittest import mock
from broker.worker import isolation

KEEP = '0 1 1\n1 0 1\n2 2 65535\n'
GATEWAY = '0 1 65536\n424242 0 1\n'  # synthetic owner-ID example
DEFAULT = '0 0 65537\n'


class OwnerMappingTests(unittest.TestCase):
    def test_keep_id_uid1_and_gateway_owner_are_same_parent_authority(self):
        self.assertIn((1, 0, 1), isolation.require_owner_mapping(KEEP, 1))
        self.assertIn((424242, 0, 1), isolation.require_owner_mapping(GATEWAY, 424242))
        # Numeric inequality is not a separate host-UID security boundary.
        with self.assertRaises(ValueError):
            isolation.require_owner_mapping(GATEWAY, 1)
        with self.assertRaises(ValueError):
            isolation.require_owner_mapping(DEFAULT, 1)

    def test_reject_overlaps_broad_owner_ranges_or_malformed_mapping(self):
        for raw in ('1 0 2', '0 0 65537', '1 0 1\n2 0 1', '1 0 1\n1 2 1',
                    '1 -1 1', '1 0 0', '1:0:1:2', '', '4294967296 0 1'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                isolation.require_owner_mapping(raw, 1)

    def test_worker_requires_private_pid_no_caps_owner_map_and_no_extra_fds(self):
        def check(*, pid=1, caps='0', maps=KEEP, fds=('0', '1', '2'), hidden_fd=False):
            status = 'CapEff: '+caps+'\nCapPrm: 0\nCapBnd: 0\nNoNewPrivs: 1\n'
            def opened(path, **_kwargs):
                return io.StringIO(status if path.endswith('status') else maps)
            st = type('Stat', (), {'st_dev': 1, 'st_ino': 2})()
            with (mock.patch.object(isolation.os, 'geteuid', return_value=1),
                  mock.patch.object(isolation.os, 'getegid', return_value=1),
                  mock.patch.object(isolation.os, 'getpid', return_value=pid),
                  mock.patch('builtins.open', side_effect=opened),
                  mock.patch.object(isolation.os, 'stat', return_value=st),
                  mock.patch.object(isolation.os, 'listdir', return_value=list(fds)),
                  mock.patch.object(isolation.os, 'readlink', side_effect=
                      FileNotFoundError() if hidden_fd else None, return_value='private pipe')):
                isolation.require_worker_isolation()
        check()
        for kwargs in ({'pid': 2}, {'caps': '1'}, {'maps': DEFAULT}, {'fds': ('0','1','2','4')}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                check(**kwargs)
        check(fds=('0','1','2','3'), hidden_fd=True)

    def test_gateway_keeps_actual_non_one_uid(self):
        with (mock.patch.object(isolation.os, 'geteuid', return_value=424242),
              mock.patch.object(isolation.os, 'getegid', return_value=424242),
              mock.patch('builtins.open', side_effect=lambda *_a, **_k: io.StringIO(GATEWAY))):
            isolation.require_gateway_owner()
