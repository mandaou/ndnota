import logging
import time
import ndn.encoding as enc
from ndn import appv2, types
from ndn.appv2 import NDNApp
from ndn.encoding import ContentType, MetaInfo
from ndn.security import Sha256WithEcdsaSigner
from Cryptodome.PublicKey import ECC

import sys
sys.path.insert(0, '/home/user/ndnota/src')
sys.path.insert(0, '/home/user/ndnota/src/common')
sys.path.insert(0, '/home/user/ndnota/src/protocol')
from common.AuthProto import MessageType, ParameterMessage, ParameterType, AuthProtoMsg
from common.utils import encrypt, decrypt
from common.Enums import State

# region logging
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.ERROR,
                    style='{')
# endregion logging


class Consumer:
    def __init__(self):
        self.state = State.IDLE
        self.app = NDNApp()
        self.kc = self.app.default_keychain()
        self.signer: Sha256WithEcdsaSigner = self.kc.get_signer({'identity': '/consumer'})
        self.signer_public_key = self.signer.key.public_key()
        self.auth_server_public_key = None
        self.challenge_token = None
        self.authentication_token = None

    async def authenticate(self):
        logging.debug('Current State: {}'.format(self.state))
        try:
            # Send request to get handshake token
            logging.debug('Preparing a handshake request message')
            hs_msg = AuthProtoMsg()
            hs_msg.ts = time.time_ns()
            hs_msg.type = MessageType.HANDSHAKE_REQUEST
            p1 = ParameterMessage()
            p1.key = ParameterType.KEY
            p1.value = self.signer_public_key.export_key(format='raw')
            hs_msg.parameters = [p1]

            name, content, context = await self.app.express(auth_server, validator=appv2.pass_all,
                                                            app_param=hs_msg.encode(), signer=self.signer,
                                                            must_be_fresh=True, can_be_prefix=False, lifetime=6000)
            logging.debug('The handshake request message has been sent to the authentication server')
            self.state = State.AUTH_REQUEST_SENT


            # Content should be of type MessageType.HANDSHAKE_REPLY, and contains:
            # 1) Auth Server public key, and 2) the encrypted challenge token

            if content is not None:
                self.state = State.HANDSHAKE_TOKEN_RECEIVED
                received_msg = AuthProtoMsg.parse(bytes(content))
                self.auth_server_public_key = ECC.import_key(received_msg.parameters[1].value, curve_name='p256')
                self.challenge_token = decrypt(self.signer.key, received_msg.parameters[0].value)
                logging.debug('The handshake token has been received from the server.')
            else:
                logging.error('ERROR - No handshake token was received.')


            # By now, we received a handshake token that is signed by AuthServ priv_key and encrypted by our pub_key
            # We should decrypt the token and send it back signed by our priv_key and encrypted AuthServ pub_key
            # Send encrypted handshake token to get encrypted authentication token

            logging.debug('Current State: {}'.format(self.state))
            logging.debug('Preparing an authentication request message')
            a_msg = AuthProtoMsg()
            a_msg.ts = time.time_ns()
            a_msg.type = MessageType.AUTHENTICATION_REQUEST
            p1 = ParameterMessage()
            p1.key = ParameterType.CHALLENGE_TOKEN
            p1.value = encrypt(self.auth_server_public_key, self.challenge_token)
            a_msg.parameters = [p1]

            name, content, context = await self.app.express(auth_server, validator=appv2.pass_all,
                                                            app_param=a_msg.encode(), signer=self.signer,
                                                            must_be_fresh=True, can_be_prefix=False, lifetime=6000)
            logging.debug('The authentication message has been sent to the authentication server')
            self.state = State.AUTH_REQUEST_SENT


            if content is not None:
                self.state = State.AUTH_TOKEN_RECEIVED
                received_msg = AuthProtoMsg.parse(bytes(content))
                self.authentication_token = received_msg.parameters[0].value
                logging.debug('The authentication token has been received from the server.')
            else:
                logging.error('ERROR - No authentication token was received.')

        except types.InterestNack as e:
            print('Nacked with reason={} at state={}'.format(e.reason, self.state))
        except types.InterestTimeout:
            print('Timeout at state={}'.format(self.state))
        except types.InterestCanceled:
            print('Canceled at state={}'.format(self.state))
        except types.ValidationFailure:
            print('Data failed to validate at state={}'.format(self.state))

        return self.authentication_token

    async def get(self, authentication_server, token, content_ndn_name):
        content_uri = enc.Name.from_str(content_ndn_name)
        app_param = None
        try:
            if token is not None:
                msg = AuthProtoMsg()
                msg.ts = time.time_ns()
                msg.type = MessageType.AUTH_TOKEN
                p1 = ParameterMessage()
                p1.key = ParameterType.AUTHENTICATION_SERVER
                p1.value = authentication_server
                p2 = ParameterMessage()
                p2.key = ParameterType.AUTHENTICATION_TOKEN
                p2.value = token
                msg.parameters = [p1, p2]
                app_param = msg.encode()

            data_name, content, pkt_context = await self.app.express(content_uri, app_param=app_param,
                                                                     signer=self.signer, validator=appv2.pass_all,
                                                                     must_be_fresh=True, can_be_prefix=False,
                                                                     lifetime=6000)

            mi: MetaInfo = pkt_context['meta_info']
            if mi.content_type == ContentType.NACK:
                received_msg = AuthProtoMsg.parse(bytes(content))
                if received_msg.type == MessageType.REDIRECT:
                    c.authentication_token = await c.authenticate()
                    return await self.get(authentication_server, c.authentication_token, content_ndn_name)
                else:
                    return bytes(received_msg.parameters[0].value)
            else:
                return bytes(content) if content else None
        except types.InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except types.InterestTimeout:
            print(f'Timeout')
        except types.InterestCanceled:
            print(f'Canceled')
        except types.ValidationFailure:
            print(f'Data failed to validate')


async def main():
    print('Client, Normal, New, Cached')
    sites = ['/om/edu/squ/www/unprotected', '/om/edu/squ/www/protected', '/om/edu/squ/www/protected2']
    timers = []
    for s in sites:
        start_timer = time.time_ns()
        reply = await c.get(enc.Name.to_str(auth_server), c.authentication_token, s)
        timers.append(time.time_ns() - start_timer)
    print('Client, {}, {}, {}'.format(timers[0], timers[1], timers[2]))
    c.app.shutdown()


if __name__ == '__main__':
    auth_server = enc.Name.from_str('/example/authserv')
    c = Consumer()
    c.app.run_forever(after_start=main())
