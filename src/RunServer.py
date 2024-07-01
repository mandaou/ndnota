import logging
import os
from threading import Thread
import sys
import subprocess

from server.AuthServer import AuthServer

# region logging
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.ERROR,
                    style='{')
# endregion logging

# region globals
AUTH_SERVER_ROUTE_PREFIX = '/example/authserv'


# endregion globals

def generate_protobuf_classes():
    logging.debug('Generate protobuf python classes .. started')
    PROTO_CMD = 'lib/protobuf/bin/protoc'
    SRC_DIR = 'protos'
    DST_DIR = 'src/protocol'
    cmd = '{} -I={} --python_out={} {}/AuthMessage.proto'.format(PROTO_CMD, SRC_DIR, DST_DIR, SRC_DIR)
    os.system(cmd)
    logging.debug('Generate protobuf python classes .. finished')


def create_auth_server_thread():
    logging.debug('Starting Auth Server thread ... ')
    a = AuthServer(AUTH_SERVER_ROUTE_PREFIX)
    t = Thread(target=a.start())
    t.daemon = True
    t.start()
    logging.debug('Auth Server thread started ... ')
    return t


def create_auth_server_process():
    p = subprocess.Popen([sys.executable, 'src/AuthServerD.py'])
    return p


if __name__ == '__main__':
    #generate_protobuf_classes()
    authserv_t = create_auth_server_thread()
    #authserv_p = create_auth_server_process()
    #time.sleep(100)


