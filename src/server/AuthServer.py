import logging
import time
from server.ClientsManager import ClientsManager
from ndn import appv2, encoding as enc
from ndn.appv2 import NDNApp
from ndn.security import Certificate, Key
import typing
from common.AuthProto import AuthProtoMsg

# region logging
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.ERROR,
                    style='{')


# endregion logging


class AuthServer:
    def __init__(self, route_prefix):
        self.app = NDNApp()
        self.route_prefix = route_prefix
        self.mgr = ClientsManager(self)
        self.kc = self.app.default_keychain()
        self.key: Key = self.kc.get(enc.Name.from_str(route_prefix)).default_key()
        self.cert: Certificate = self.key.default_cert()
        self.signer = self.kc.get_signer({'identity': '/example/authserv'})

        @self.app.route(route_prefix, validator=appv2.pass_all)
        def on_interest(name: enc.FormalName, _app_param: typing.Optional[enc.BinaryStr],
                        reply: appv2.ReplyFunc, context: appv2.PktContext):
            start_timer = time.time_ns()
            msg = AuthProtoMsg.parse(bytes(_app_param))
            sig_ptrs = context['sig_ptrs']
            content = self.mgr.process(msg, sig_ptrs, time.time_ns() - start_timer)
            reply(self.app.make_data(name, content=content, signer=self.signer, freshness_period=10000))

    def start(self):
        logging.debug('Instantiating a new Authentication Server and binding it to: {}'.format(self.route_prefix))
        try:
            self.app.run_forever()
        except ConnectionRefusedError:
            exit('NFD is not running .. exiting')
