from enum import Flag, Enum
from ndn.encoding import BytesField, MapField, ModelField, NameField, RepeatedField, TlvModel, UintField


class MessageType(Flag):
    UNSPECIFIED = 0
    REDIRECT = 1
    HANDSHAKE_REQUEST = 2
    HANDSHAKE_REPLY = 3
    AUTHENTICATION_REQUEST = 4
    AUTHENTICATION_REPLY = 5
    AUTH_TOKEN = 6
    IS_CONSUMER_AUTHENTICATED = 7
    AUTHENTICATED = 8
    ERROR = 9


class ParameterType(Flag):
    UNSPECIFIED = 0
    AUTHENTICATION_SERVER = 1
    KEY = 2
    CHALLENGE_TOKEN = 3
    AUTHENTICATION_TOKEN = 4
    IS_AUTHENTICATED = 5
    ERROR_MESSAGE = 6


class ParameterMessage(TlvModel):
    key = UintField(0x174, val_base_type=ParameterType)
    value = BytesField(0x175)


class AuthProtoMsg(TlvModel):
    ts = UintField(0x171)
    type = UintField(0x172, val_base_type=MessageType)
    parameters = RepeatedField(ModelField(0x173, ParameterMessage))

