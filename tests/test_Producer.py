from unittest import TestCase

from ndn import appv2, types
from ndn.appv2 import NDNApp
import ndn.encoding as enc


class TestProducer(TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.app = NDNApp()
        cls.root_string = '/om/edu/squ/www'
        cls.root = enc.Name.from_str(cls.root_string)
        cls.unprotected_string = '/om/edu/squ/www/unprotected'
        cls.unprotected = enc.Name.from_str(cls.unprotected_string)
        cls.protected_string = '/om/edu/squ/www/protected'
        cls.protected = enc.Name.from_str(cls.protected_string)

    async def body(self, name):
        try:
            data_name, content, pkt_context = await self.app.express(name, validator=appv2.pass_all, must_be_fresh=True,
                                                                     can_be_prefix=False, lifetime=6000)
            print(f'Received Data Name: {enc.Name.to_str(data_name)}')
            print(pkt_context['meta_info'])
            print(bytes(content) if content else None)
        except types.InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except types.InterestTimeout:
            print(f'Timeout')
        except types.InterestCanceled:
            print(f'Canceled')
        except types.ValidationFailure:
            print(f'Data failed to validate')
        finally:
            self.app.shutdown()

    def test_content_root(self):
        self.app.run_forever(after_start=self.body(self.root))

    def test_unprotected_content(self):
        self.app.run_forever(after_start=self.body(self.unprotected))

    def test_protected_content(self):
        self.app.run_forever(after_start=self.body(self.protected))
