import time

from Cryptodome.PublicKey.ECC import EccKey
from common.Enums import State


class ClientSession:
    def __init__(self, key_locator, public_key: EccKey):
        self.auth_request_received_ts = time.time_ns()
        self.state = State.AUTH_REQUEST_RECEIVED
        self.key_locator = key_locator
        self.pubkey = public_key
        self.hs_token = None
        self.auth_token = None

    def __repr__(self):
        s = {'ts': self.auth_request_received_ts,
             'state': self.state,
             'key': self.key_locator,
             'pubkey': self.pubkey,
             'hs_token': self.hs_token,
             'auth_token': self.auth_token}
        return str(s)
