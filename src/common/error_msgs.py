import sys
import time

sys.path.insert(0, '/home/user/ndnota/src/common')
from common.AuthProto import AuthProtoMsg, MessageType, ParameterMessage, ParameterType


def get_err_msg(err_type):
    e_msg = AuthProtoMsg()
    e_msg.timestamp = time.time_ns()
    e_msg.type = MessageType.ERROR
    p1 = ParameterMessage()
    p1.key = ParameterType.ERROR_MESSAGE
    p1.value = "Unknown error !!"
    match err_type:
        case 'invalid':
            p1.value = 'Invalid message type'
        case 'invalid_challenge_token':
            p1.value = 'Invalid challenge token'
        case 'invalid_auth_token':
            p1.value = 'Invalid authentication token'
        case 'unknown':
            p1.value = 'Unknown message state'
        case 'missing_hand_shake':
            p1.value = 'Not a valid session, session should start with a handshake message'
        case 'unsigned_interest':
            p1.value = 'Can\'t serve unsigned interests'
        case 'not_authenticated':
            p1.value = 'Can\'t serve protected content for unauthenticated users'
    e_msg.parameters = [p1]
    return e_msg.encode()
