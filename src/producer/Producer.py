import logging
import time

from Cryptodome.PublicKey.ECC import EccKey
from ndn import appv2, encoding as enc
from ndn.appv2 import NDNApp
from ndn.encoding import ContentType, MetaInfo
from ndn.security import Keychain, Sha256WithEcdsaSigner
import sys

sys.path.insert(0, '/home/user/ndnota/src')
sys.path.insert(0, '/home/user/ndnota/src/protocol')
sys.path.insert(0, '/home/user/ndnota/src/common')
from common.error_msgs import get_err_msg
from common.AuthProto import AuthProtoMsg, MessageType, ParameterMessage, ParameterType
import NDNAgent

# region logging
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%H:%M:%S',
                    level=logging.ERROR,
                    style='{')


# endregion logging


class Producer:
    def __init__(self, identity, content_root_uri, auth_servers):
        logging.debug('Starting the initializing a new producer')
        self.route_prefix = content_root_uri
        self.content_protected = self.route_prefix + '/protected'
        self.content_protected2 = self.route_prefix + '/protected2'
        self.content_unprotected = self.route_prefix + '/unprotected'
        self.app = NDNApp()
        self.kc: Keychain = self.app.default_keychain()
        self.kl = identity + '/KEY'
        self.signer: Sha256WithEcdsaSigner = self.kc.get_signer({'identity': identity})
        self.key: EccKey = self.signer.key
        self.public_key: EccKey = self.key.public_key()
        self.auth_servers = auth_servers
        self.app.attach_handler(self.route_prefix, self.base_handler, appv2.pass_all)
        self.cache = []
        logging.debug('Finished the initializing of the new producer')

    def base_handler(self, name: enc.FormalName, _app_param: enc.BinaryStr | None,
                     reply: appv2.ReplyFunc, context: appv2.PktContext) -> None:
        base_timer = time.time_ns()
        n = enc.Name.to_str(name[:-1])
        mi = MetaInfo()
        mi.content_type = ContentType.BLOB

        if n == self.content_protected or n == self.content_protected2:
            phase = 'PROTECTED'
            # Check for authentication since it is a protected area
            sig_info = context['sig_ptrs'].signature_info

            if sig_info is None:
                mi.content_type = ContentType.NACK
                content = get_err_msg('unsigned_interest')
            else:
                is_authenticated = False

                # If possible, get the token from app_parameter and send it to the AuthServ for verification.
                if bytes(_app_param) != '':
                    received_msg = AuthProtoMsg.parse(bytes(_app_param))

                    if len(received_msg.parameters) > 0:
                        client_auth_server = bytes(received_msg.parameters[0].value).decode()
                        kl = enc.Name.to_str(sig_info.key_locator.name)

                        if kl in self.cache:
                            phase = 'PROTECTED-CACHED'
                            logging.debug('CACHE FOUND => {}'.format(kl))
                            is_authenticated = True
                        else:
                            phase = 'PROTECTED-NEW'
                            is_authenticated_timer = time.time_ns()
                            is_authenticated = NDNAgent.is_client_authenticated(client_auth_server, kl, _app_param)
                            print('PRODUCER, IS_AUTHENTICATED, {}, IS_AUTHENTICATED'.format(time.time_ns() - is_authenticated_timer))
                            if is_authenticated:
                                self.cache.append(kl)

                # print('Trying to access {} while IsAuthenticated={} from: {}'
                #       .format(n, is_authenticated, enc.Name.to_str(sig_info.key_locator.name)))

                if is_authenticated:
                    content = "Wohoo !! Protected content is always served for our lovely authenticated users".encode()
                else:
                    # This takes place when accessing protected and there is no auth_token
                    phase = 'REDIRECT'
                    mi.content_type = ContentType.NACK
                    redirect_msg = AuthProtoMsg()
                    redirect_msg.ts = time.time_ns()
                    redirect_msg.type = MessageType.REDIRECT
                    p1 = ParameterMessage()
                    p1.key = ParameterType.AUTHENTICATION_SERVER
                    p1.value = self.auth_servers[0]
                    redirect_msg.parameters = [p1]
                    content = redirect_msg.encode()
        else:
            phase = 'NORMAL'
            content = "Normal Content".encode()

        reply(self.app.make_data(name, meta_info=mi, content=content, signer=self.signer, freshness_period=10000))
        print('PRODUCER, BASE_HANDLER_RESPONSE, {}, {}'.format(time.time_ns() - base_timer, phase))

    async def reg(self):
        # logging.debug('Registering NFD Route -> {}'.format(self.kl))
        # await self.app.register(self.kl)
        logging.debug('Registering NFD Route -> {}'.format(self.route_prefix))
        await self.app.register(self.route_prefix)

    def start(self):
        logging.debug('Instantiating a new Producer Server and binding it to: {}'.format(self.route_prefix))
        try:

            self.app.run_forever(after_start=self.reg())
        except ConnectionRefusedError:
            exit('NFD is not running .. exiting')
