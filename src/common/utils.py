import secrets
import string
import pickle

import Cryptodome.Random
from ndn.encoding import BinaryStr
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import HKDF


def gen_random_string(length=16):
    # alphabet = string.ascii_letters + string.digits + string.punctuation
    # code = ''.join(secrets.choice(alphabet) for i in range(length))
    code = Cryptodome.Random.get_random_bytes(length)
    return code


def obj2pickle(obj, file):
    with open(file, 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def pickle2obj(file):
    with open(file, 'rb') as f:
        obj = pickle.load(f)
    return obj


def get_key_length(key: ECC.EccKey) -> int:
    if key.curve == 'NIST P-256' or key.curve == 'Ed25519':
        return 32
    elif key.curve == 'NIST P-384':
        return 48
    elif key.curve == 'Ed448':
        return 56
    else:
        raise ValueError(f'Unsupported curve for ECIES: {key.curve}')


def encrypt(pub_key: ECC.EccKey, content: BinaryStr) -> bytes:
    """
    Encrypt a message with an ECC key

    :param pub_key: the public key, using the curve secp256r1 or ed25519.
    :param content: the message to encrypt.
    :return: cipher text.
    """
    key_len = get_key_length(pub_key)
    # ephemeral key
    ek = ECC.generate(curve=pub_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = pub_key.pointQ * ek.d
    p_bytes = int(p.x).to_bytes(key_len, 'big') + int(p.y).to_bytes(key_len, 'big')
    ek_q = ek.public_key().pointQ
    ek_q_bytes = int(ek_q.x).to_bytes(key_len, 'big') + int(ek_q.y).to_bytes(key_len, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM)

    encrypted, tag = cipher.encrypt_and_digest(content)
    ret = bytearray()
    ret.extend(ek_q_bytes)
    ret.extend(cipher.nonce)
    ret.extend(tag)
    ret.extend(encrypted)
    return bytes(ret)


def decrypt(pri_key: ECC.EccKey, cipher_text: BinaryStr) -> bytes:
    """
    Decrypt a message encrypted with an ECC key.

    :param pri_key: the private key, using curve secp256r1.
    :param cipher_text: the cipher text.
    :return: decrypted message.
    :raises ValueError: if the decryption failed.
    """
    key_len = get_key_length(pri_key)
    aes_offset = key_len * 2
    ek_q_bytes = bytes(cipher_text[0:aes_offset])
    nonce = bytes(cipher_text[aes_offset:aes_offset + 16])
    tag = cipher_text[aes_offset + 16:aes_offset + 32]
    encrypted = cipher_text[aes_offset + 32:]

    # ephemeral key
    ek_q = ECC.EccPoint(x=int.from_bytes(ek_q_bytes[:key_len], 'big'),
                        y=int.from_bytes(ek_q_bytes[key_len:], 'big'),
                        curve=pri_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = ek_q * pri_key.d
    p_bytes = int(p.x).to_bytes(key_len, 'big') + int(p.y).to_bytes(key_len, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted, tag)
    #return cipher.decrypt(encrypted)


def enco(pub_key: ECC.EccKey, content: BinaryStr):
    cipher = AES.new(pub_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(content)
    return ciphertext, nonce, tag


def deco(pri_key: ECC.EccKey, cipher_text: BinaryStr, nonce, tag) -> bytes:
    cipher = AES.new(pri_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(cipher_text)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
    except ValueError:
        print("Key incorrect or message corrupted")
    return plaintext
