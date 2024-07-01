import logging
import time
import Cryptodome.Random
import ndn.encoding as enc
from Cryptodome.PublicKey import ECC
from Cryptodome.Util.asn1 import DerSequence
from common.Enums import State
from server.ClientSession import ClientSession
from common.AuthProto import AuthProtoMsg, MessageType, ParameterMessage, ParameterType
from common.utils import encrypt, decrypt
from common.error_msgs import get_err_msg


class ClientsManager:
    def __init__(self, authentication_server):
        self.sessions = list()
        self.parent = authentication_server

    def __repr__(self):
        repr(self.sessions)

    def process(self, msg: AuthProtoMsg, sig_ptrs: enc.SignaturePtrs, msg_parsing_time) -> bytearray | memoryview:
        start_time = time.time_ns()

        # State Machine
        match msg.type:
            case MessageType.UNSPECIFIED:
                return get_err_msg('invalid')

            case MessageType.HANDSHAKE_REQUEST:
                logging.debug('Auth message received in Handshake')
                kl = enc.Name.to_str(sig_ptrs.signature_info.key_locator.name)
                session = self.find_session_by_key(kl)

                if session is None:
                    received_public_key = ECC.import_key(msg.parameters[0].value, curve_name='p256')
                    # Check signature
                    DerSequence().decode(bytes(sig_ptrs.signature_value_buf))
                    session = ClientSession(kl, received_public_key)
                    self.sessions.append(session)

                hs_msg = AuthProtoMsg()
                hs_msg.ts = time.time_ns()
                hs_msg.type = MessageType.HANDSHAKE_REPLY
                p1 = ParameterMessage()
                p1.key = ParameterType.CHALLENGE_TOKEN
                session.hs_token = Cryptodome.Random.get_random_bytes(16)
                p1.value = encrypt(session.pubkey, session.hs_token)
                p2 = ParameterMessage()
                p2.key = ParameterType.KEY
                p2.value = self.parent.signer.key.public_key().export_key(format='raw')
                hs_msg.parameters = [p1, p2]
                content = hs_msg.encode()

                # Update the session state
                session.state = State.HANDSHAKE_TOKEN_SENT
                logging.debug('HANDSHAKE_REPLY message has been prepared. Transitioning into {}'.format(session.state))

            case MessageType.AUTHENTICATION_REQUEST:
                logging.debug('Auth message request received in Authenticate')
                kl = enc.Name.to_str(sig_ptrs.signature_info.key_locator.name)

                session = self.find_session_by_key(kl)

                if session is None:
                    return get_err_msg('missing_hand_shake')

                # Check if Handshake token is correct
                if session.hs_token != decrypt(self.parent.signer.key, msg.parameters[0].value):
                    return get_err_msg('invalid_challenge_token')

                logging.debug('The received challenge token matches our stored one')
                a_msg = AuthProtoMsg()
                a_msg.ts = time.time_ns()
                a_msg.type = MessageType.AUTHENTICATION_REPLY
                p1 = ParameterMessage()
                p1.key = ParameterType.AUTHENTICATION_TOKEN
                session.auth_token = Cryptodome.Random.get_random_bytes(16)
                p1.value = encrypt(self.parent.signer.key, session.auth_token)
                a_msg.parameters = [p1]
                content = a_msg.encode()

                # Update the session state
                session.state = State.AUTH_TOKEN_SENT
                logging.debug('AUTHENTICATION_REPLY message has been prepared. Transitioning into {}'.format(session.state))

            case MessageType.IS_CONSUMER_AUTHENTICATED:
                logging.debug('Auth message received in Is Consumer Authenticated')
                consumer_kl = msg.parameters[0].value
                consumer_auth_token = bytes(msg.parameters[1].value)
                decrypted_consumer_auth_token = decrypt(self.parent.signer.key, consumer_auth_token)

                session = self.find_session_by_key(consumer_kl)
                ia_result: bool = True if decrypted_consumer_auth_token == session.auth_token else False

                if not ia_result:
                    logging.debug('Received token does not match the stored one => {} != {}'
                                  .format(decrypted_consumer_auth_token, session.auth_token))

                ia_msg = AuthProtoMsg()
                ia_msg.ts = time.time_ns()
                ia_msg.type = MessageType.AUTHENTICATED
                p1 = ParameterMessage()
                p1.key = ParameterType.IS_AUTHENTICATED
                p1.value = 'True'.encode() if ia_result else 'False'.encode()
                ia_msg.parameters = [p1]
                content = ia_msg.encode()

            case _:
                logging.debug('Auth message received in UNKNOWN state')
                return get_err_msg('unknown')

        print('SERVER, {}, {}, {}'.format(msg.type, msg_parsing_time, time.time_ns() - start_time))
        return content

    def find_session_by_key(self, key_locator: memoryview | bytes | str) -> ClientSession:
        k = None

        if isinstance(key_locator, memoryview):
            k = bytes(key_locator).decode()
        elif isinstance(key_locator, bytes):
            k = key_locator.decode()
        else:
            k = key_locator

        logging.debug('Trying to find a session for KL={}'.format(k))
        for i in self.sessions:
            if i.key_locator == k:
                logging.debug('A session has been found for {}'.format(k))
                return i
        logging.debug('No session was found for KL={}'.format(k))

    def print(self):
        i = 1
        for s in self.sessions:
            print('({}) {}'.format(i, s))


