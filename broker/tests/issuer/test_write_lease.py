"""Operational lease with fabricated HTTP/JWT only; never read a live key."""
import unittest
from broker.issuer import read_base
from broker.issuer.write_lease import WriteLease
from broker.tests.issuer.test_write_token import FakeRequest, NOW, JWT, REPO, TOKEN, grant


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.config = read_base.DeployConfig(101, 202, REPO, '/fixture/missing.pem')

    def lease(self, request):
        return WriteLease(self.config, request=request, jwt=lambda: JWT, clock=lambda: NOW)

    def test_minimal_grant_two_live_guards_revocation_and_one_use(self):
        request = FakeRequest()
        guards = []
        lease = self.lease(request)
        def guard():
            guards.append(len(request.calls))
            return True
        observed = []
        self.assertEqual(lease.deliver_once(lambda token: observed.append(token) or 'sanitized', guard), 'sanitized')
        self.assertEqual(guards, [0, 1])
        self.assertEqual(observed, [TOKEN])
        self.assertEqual(request.calls[0][3], {'repositories': ['fixture-repository'], 'permissions': {'contents': 'write'}})
        self.assertEqual(request.calls[-1][:3], ('DELETE', '/installation/token', TOKEN))
        with self.assertRaises(read_base.IssuerError):
            lease.deliver_once(lambda _: None, guard)
        self.assertEqual(len(request.calls), 2)

    def test_denied_current_never_mints(self):
        request = FakeRequest()
        with self.assertRaises(read_base.IssuerError):
            self.lease(request).deliver_once(lambda _: self.fail('transport'), lambda: False)
        self.assertEqual(request.calls, [])

    def test_broadened_grants_are_revoked_never_delivered(self):
        for changes in ({'repositories': [{'full_name': 'Other/repo'}]},
                        {'permissions': {'contents': 'write', 'issues': 'write'}},
                        {'repository_selection': 'all'}):
            request = FakeRequest(grant(**changes))
            with self.subTest(changes=changes), self.assertRaises(read_base.IssuerError):
                self.lease(request).deliver_once(lambda _: self.fail('transport'), lambda: True)
            self.assertEqual(request.calls[-1][0], 'DELETE')

    def test_stale_delivery_and_transport_failure_always_revoke(self):
        for transport_error in (False, True):
            request = FakeRequest()
            guards = iter((True, transport_error))
            def transport(_token):
                raise ValueError('fixture transport failed')
            with self.assertRaises((read_base.IssuerError, ValueError)):
                self.lease(request).deliver_once(transport, lambda: next(guards))
            self.assertEqual(request.calls[-1][0], 'DELETE')

    def test_revocation_failure_cannot_report_success(self):
        request = FakeRequest(revoke_error=ValueError('private fixture detail'))
        with self.assertRaisesRegex(read_base.IssuerError, '^revocation_uncertain_inspect_no_retry$'):
            self.lease(request).deliver_once(lambda _: {'acknowledged': True}, lambda: True)
