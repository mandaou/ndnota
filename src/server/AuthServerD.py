import logging

from AuthServer import AuthServer
import daemon
import os

# region logging
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')
# endregion logging


def main(auth_server_route_prefix):
    logging.debug('Daemonizing Auth Server .. ')

    a = AuthServer(auth_server_route_prefix)
    with daemon.DaemonContext(detach_process=False):
        os.system('echo {} > /var/run/user/1000/authserv.pid'.format(os.getpid()))
        a.start()


if __name__ == '__main__':
    main(auth_server_route_prefix='/example/authserv')

