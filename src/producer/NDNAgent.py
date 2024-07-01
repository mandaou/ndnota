import time
from ndn import appv2, types
from common.AuthProto import AuthProtoMsg, MessageType, ParameterMessage, ParameterType
from threading import Thread


class CheckIfAuthenticated(Thread):
    def __init__(self, server_name, client_key_locator, client_auth_token_msg):
        self.app = appv2.NDNApp()
        self.auth_server = server_name
        self.kc = self.app.default_keychain()
        self.signer = self.kc.get_signer({'identity': '/om/edu/squ'})
        self.client_key = client_key_locator
        self.client_auth_token_msg = client_auth_token_msg
        self.result = None
        super(CheckIfAuthenticated, self).__init__()

    async def is_client_authenticated_async(self):
        try:
            c_msg = AuthProtoMsg()
            c_msg.ts = time.time_ns()
            c_msg.type = MessageType.IS_CONSUMER_AUTHENTICATED
            p1 = ParameterMessage()
            p1.key = ParameterType.KEY
            p1.value = self.client_key
            p2 = ParameterMessage()
            p2.key = ParameterType.AUTHENTICATION_TOKEN
            p2.value = AuthProtoMsg.parse(bytes(self.client_auth_token_msg)).parameters[1].value
            c_msg.parameters = [p1, p2]

            data_name, content, pkt_context = await self.app.express(
                self.auth_server, app_param=c_msg.encode(), validator=appv2.pass_all,
                signer=self.signer, must_be_fresh=True, can_be_prefix=False, lifetime=6000)

            rmsg = AuthProtoMsg.parse(bytes(content))
            isauth_token = bool(bytes(rmsg.parameters[0].value).decode())
            self.result = isauth_token
        except types.InterestNack as e:
            self.result = False
            print(f'Nacked with reason={e.reason}')
        except types.InterestTimeout:
            self.result = False
            print(f'Timeout')
        except types.InterestCanceled:
            self.result = False
            print(f'Canceled')
        except types.ValidationFailure:
            self.result = False
            print(f'Data failed to validate')
        finally:
            self.app.shutdown()

    def run(self):
        self.app.run_forever(after_start=self.is_client_authenticated_async())


def is_client_authenticated(auth_server, client_key, token):
    t = CheckIfAuthenticated(auth_server, client_key, token)
    t.start()
    t.join()
    return t.result
