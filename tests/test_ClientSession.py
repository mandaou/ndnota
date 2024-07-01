from unittest import TestCase
from ndn.appv2 import NDNApp
import ndn.encoding as enc

from server.ClientSession import ClientSession
from server.ClientsManager import ClientsManager


class TestClientSession(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.app = NDNApp()
        cls._face = cls.app.face
        cls.mgr = ClientsManager()


    def test_instantiate(self):
        i1, i1_final_name = enc.make_interest('/example/authserv',
                                              enc.InterestParam(must_be_fresh=True, lifetime=6000),
                                              need_final_name=True)
        name, i_param, a_param, sig_ptrs = enc.parse_interest(i1)
        self.mgr.process(i1)
