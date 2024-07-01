import unittest
from unittest import TestCase
from ndn import appv2
import ndn.encoding as enc
from ndn.appv2 import NDNApp
from ndn.encoding import SignatureInfo
from ndn.security import Certificate, Identity, Key, NullSigner
import typing


class TestNDNKeyChain(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.n = enc.Name.from_str('/example/authserv')
        cls.app = NDNApp()
        cls.kc = cls.app.default_keychain()
        cls.identity = cls.kc.get(cls.n)
        cls.identity_key = cls.identity.default_key()
        cls.identity_cert = cls.identity_key.default_cert()

    def test_types(self):
        self.assertIsInstance(self.identity, Identity)
        self.assertEqual(self.n, self.identity.name)
        self.assertIsNotNone(self.identity_key)
        self.assertIsInstance(self.identity_key, Key)
        self.assertIsNotNone(self.identity_cert)
        self.assertIsInstance(self.identity_cert, Certificate)

    def test_interest(self):
        i1, i1_final_name = enc.make_interest(self.n,
                                              enc.InterestParam(must_be_fresh=True, lifetime=6000),
                                              app_param='app params go here '.encode(),
                                              signer=NullSigner(),
                                              need_final_name=True)
        name, i_param, a_param, sig_ptrs = enc.parse_interest(i1)
        signer = self.kc.get_signer({})
        sig_info = SignatureInfo()
        x = 1

