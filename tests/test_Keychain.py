from unittest import TestCase

from Cryptodome.PublicKey import ECC
from Cryptodome.PublicKey.ECC import EccKey
from ndn.app_support.keychain_register import KcHandler
from ndn.appv2 import NDNApp
import ndn.encoding as enc
from ndn.security import Certificate, Identity
from ndn.app_support import security_v2 as secv2

from server.ClientSession import ClientSession
from server.ClientsManager import ClientsManager


class TestClientSession(TestCase):
    def setUp(self):
        self.app = NDNApp()
        self.kc = self.app.default_keychain()

    def test_print(self):
        for name, ident in self.kc.items():
            n = enc.Name.to_str(name)
            i = enc.Name.to_str(ident.name)
            identity: Identity = ident
            reg_name = name + [secv2.KEY_COMPONENT]
            handler = KcHandler(ident)
            for j, k in identity.items():
                if enc.Name.to_str(j) == '/md/KEY/h%22%17%60%0B%EE3I':
                    for v, w in k.items():
                        cert: Certificate = w
                        ck = enc.Name.to_str(cert.key)
                        cd = cert.data
                        md = self.kc.get_signer({'identity': '/md'})
                        pk: EccKey = md.key.public_key()
                        pkder = pk.export_key(format='DER')
                        hpa = pk.has_private()
                        epk = pk.export_key(format='raw')
                        ooo = 1
        x = 1