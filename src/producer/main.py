import logging
from Producer import Producer


# region logging
# datefmt='%Y-%m-%d %H:%M:%S',
logging.basicConfig(format='{asctime} {levelname} [{filename}:{lineno}] {message}',
                    datefmt='%H:%M:%S',
                    level=logging.DEBUG,
                    style='{')
# endregion logging


if __name__ == '__main__':
    logging.debug('Instantiating a producer')
    p = Producer('/om/edu/squ', '/om/edu/squ/www', ['/example/authserv'])
    logging.debug('Starting the producer')
    p.start()
