import time

from Cryptodome import Random
from Cryptodome.PublicKey.ECC import EccKey
from ndn.app import NDNApp
from ndn.security import Keychain, Sha256WithEcdsaSigner
from common.utils import encrypt, decrypt


def run():
    s: Sha256WithEcdsaSigner = kc.get_signer({'identity': '/consumer'})
    key: EccKey = s.key
    public_key: EccKey = key.public_key()

    encoding_timer = time.time_ns()
    encoded_text = Random.get_random_bytes(16)
    encoding_duration = time.time_ns() - encoding_timer

    encryption_timer = time.time_ns()
    cipher_text = encrypt(public_key, encoded_text)
    encryption_duration = time.time_ns() - encryption_timer

    decryption_timer = time.time_ns()
    decrypted_text = decrypt(key, cipher_text)
    decryption_duration = time.time_ns() - decryption_timer

    print('{}, {}, {}'.format(encoding_duration, encryption_duration, decryption_duration))


if __name__ == '__main__':
    app: NDNApp = NDNApp()
    kc: Keychain = app.keychain
    print('token_gen, encryption_duration, decryption_duration')
    for i in range(1000):
        run()
