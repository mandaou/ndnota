from enum import Enum, auto


class State(Enum):
    IDLE = 1
    AUTH_REQUEST_SENT = 2
    AUTH_REQUEST_RECEIVED = 3
    HANDSHAKE_TOKEN_SENT = 4
    HANDSHAKE_TOKEN_RECEIVED = 5
    AUTH_TOKEN_SENT = 6
    AUTH_TOKEN_RECEIVED = 7
    AUTH_COMPLETED = 8


class ClientState(Enum):
    IDLE = 1
    WAIT_AUTH_REQUEST = 2
    WAIT_HANDSHAKE_TOKEN = 3
    WAIT_AUTH_TOKEN = 4
    AUTH_COMPLETED = 5


class FSM(Enum):
    IDLE = auto()
    AUTH_REQUEST_SENT = auto()
    AUTH_REQUEST_RECEIVED = auto()
    HANDSHAKE_TOKEN_SENT = auto()
    HANDSHAKE_TOKEN_RECEIVED = auto()
    AUTH_TOKEN_SENT = auto()
    AUTH_TOKEN_RECEIVED = auto()
    AUTH_COMPLETED = auto()