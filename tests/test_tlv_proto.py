import time
from unittest import TestCase
from ndn import appv2, types
from ndn.appv2 import NDNApp
import ndn.encoding as enc
#import common.AuthProto as p
from common.AuthProto import AuthProtoMsg, MessageType, ParameterType, ParameterMessage


class TestAuthProto(TestCase):
    def setUp(self):
        self.msg = AuthProtoMsg()

    def test_handshake(self):
        self.msg = AuthProtoMsg()
        self.msg.ts = time.time_ns()
        self.msg.type = MessageType.HANDSHAKE_REQUEST
        print(self.msg)
        print(self.msg.encode())

    def test_handshake_token(self):
        self.msg = AuthProtoMsg()
        self.msg.ts = time.time_ns()
        self.msg.type = MessageType.HANDSHAKE_REPLY
        print(self.msg)
        print(self.msg.encode())
        param_token = 'handshake_token'
        param_token_expiry = str(time.time_ns()) # + (2 * 60 * 1000000000)

        p1 = ParameterMessage()
        p1.key = ParameterType.CHALLENGE_TOKEN.value
        p1.value = param_token
        print(p1)
        p2 = ParameterMessage()
        p2.key = ParameterType.CHALLENGE_TOKEN_EXPIRY.value
        p2.value = param_token_expiry
        print(p2)
        self.msg.parameters.append(p1)
        self.msg.parameters.append(p2)
        self.msg.parameters = [p1, p2]

        # self.msg.parameters = {
        #     ParameterType.HANDSHAKE_TOKEN.value: param_token,
        #     ParameterType.HANDSHAKE_TOKEN_EXPIRY.value: str(param_token_expiry)
        # }
        print(self.msg)
        print(self.msg.encode())
