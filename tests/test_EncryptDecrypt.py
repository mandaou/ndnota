from unittest import TestCase

import Cryptodome.Signature.eddsa
from Cryptodome.PublicKey.ECC import EccKey
from Cryptodome.Util.asn1 import DerSequence
from ndn.appv2 import NDNApp
import ndn.encoding as enc
from ndn.encoding import Interest, InterestParam, SignaturePtrs
from ndn.security import Sha256WithEcdsaSigner
from ndn.security.keychain.keychain_sqlite3 import Identity, Key, Certificate
from ndn.app_support import ecies
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import HKDF
from common.utils import encrypt, decrypt, enco, deco
import Cryptodome.Random
from common import utils
from common.AuthProto import AuthProtoMsg


class TestEncryptDecrypt(TestCase):
    def setUp(self):
        self.app = NDNApp()
        self.kc = self.app.default_keychain()

        self.consumer_signer: Sha256WithEcdsaSigner = self.kc.get_signer({'identity': '/consumer'})
        self.consumer_identity = self.kc.get(enc.Name.from_str('/consumer'))
        self.consumer_key = self.consumer_identity.default_key()
        self.consumer_keybits = self.consumer_key.key_bits
        self.consumer_pubkey = ECC.import_key(self.consumer_keybits)
        self.consumer_cert = self.consumer_key.default_cert()

        self.producer_signer: Sha256WithEcdsaSigner = self.kc.get_signer({'identity': '/om/edu/squ/www'})
        self.producer_identity = self.kc.get(enc.Name.from_str('/om/edu/squ/www'))
        self.producer_key = self.producer_identity.default_key()
        self.producer_keybits = self.producer_key.key_bits
        self.producer_pubkey = ECC.import_key(self.producer_keybits)
        self.producer_cert = self.producer_key.default_cert()
        self.producer_signer: Sha256WithEcdsaSigner = self.kc.get_signer({'identity': '/example/authserv'})

        self.authserv_identity = self.kc.get(enc.Name.from_str('/example/authserv'))
        self.authserv_key = self.authserv_identity.default_key()
        self.authserv_keybits = self.authserv_key.key_bits
        self.authserv_pubkey = ECC.import_key(self.authserv_keybits)
        self.authserv_cert = self.authserv_key.default_cert()

        self.identities = [self.consumer_identity, self.producer_identity, self.authserv_identity]
        self.keys = [self.consumer_key, self.producer_key, self.authserv_key]
        self.pubkeys = [self.consumer_pubkey, self.producer_pubkey, self.authserv_pubkey]
        self.certs = [self.consumer_cert, self.producer_cert, self.authserv_cert]

    def test1(self):
        for i in self.identities:
            i: Identity = i
            print(enc.Name.to_str(i.name))
        for k in self.keys:
            k: Key = k
            print(k.key_bits)
        for p in self.pubkeys:
            p: EccKey = p
            print(p)
        for c in self.certs:
            c: Certificate = c
            print(enc.Name.to_str(c.key))
            print(enc.Name.to_str(c.name))
            print(c.data)

    def test2(self):
        plain_text = 'hello, this is a plain text string'
        encoded_text = plain_text.encode()
        print(plain_text)
        print(encoded_text)

    def test3(self):
        s: Sha256WithEcdsaSigner = self.consumer_signer
        k: EccKey = s.key
        print(k.has_private())
        plain_text = 'hello, this is a plain text string'
        encoded_text = plain_text.encode()
        cipher_text = encrypt(k, encoded_text)
        decrypted_text = decrypt(k, cipher_text)
        self.assertEqual(decrypted_text, encoded_text)

    def test4(self):
        raw_packet = utils.pickle2obj('/home/user/ndnota/raw_packet.pkl')
        i: Interest = enc.parse_interest(raw_packet)
        name = enc.Name.to_str(i[0])
        int_param: InterestParam = i[1]
        auth_proto_msg = AuthProtoMsg.parse(bytes(i[2]))
        sp: SignaturePtrs = i[3]
        digest_value_buf = str(bytes(sp.digest_value_buf))
        signature_info = sp.signature_info
        signature_value_buf = bytes(sp.signature_value_buf)
        key_locator = enc.Name.to_str(signature_info.key_locator.name)
        pubkey_by_key_locator: Sha256WithEcdsaSigner = self.kc.get_signer(
            {'key_locator': signature_info.key_locator.name})
        z = pubkey_by_key_locator.key.public_key().has_private()
        der: DerSequence = DerSequence().decode(signature_value_buf)
        der_encoded = der.encode()
        dpl = der.payload
        consumer_ecc_key: EccKey = self.consumer_signer.key
        consumer_der = consumer_ecc_key.public_key().export_key(format='DER')
        consumer_k = ECC.import_key(consumer_der)
        k0 = ECC.import_key(der_encoded, curve_name='p256')

        # ckb1 = consumer_ecc_key.export_key(format='raw')
        consumer_public_key: EccKey = consumer_ecc_key.public_key()
        ckb2 = consumer_public_key.export_key(format='raw')
        k2 = ECC.import_key(ckb2, curve_name='p256')
        b1 = consumer_ecc_key.has_private()
        b2 = consumer_public_key.has_private()
        # k = ECC.import_key(der.payload, curve_name='NIST P-256')

        # digest_covered_part = sp.digest_covered_part
        # signature_covered_part = sp.signature_covered_part
        x = 1

    def test5(self):
        s: Sha256WithEcdsaSigner = self.consumer_signer
        key: EccKey = s.key
        b1 = key.has_private()
        public_key: EccKey = key.public_key()
        b2 = public_key.has_private()

        # encoded_text = Cryptodome.Random.get_random_bytes(16)
        encoded_text = 'hello'.encode()
        cipher_text = encrypt(public_key, encoded_text)
        decrypted_text = decrypt(key, cipher_text)
        self.assertEqual(decrypted_text, encoded_text)

    def test6(self):
        s: Sha256WithEcdsaSigner = self.consumer_signer
        prikey: EccKey = s.key
        pubkey: EccKey = prikey.public_key()
        encoded_text = 'hello'.encode()
        cipher_text, nonce, tag = enco(pubkey, encoded_text)
        decrypted_text = deco(prikey, cipher_text, nonce, tag)
        self.assertEqual(decrypted_text, encoded_text)

    def test7(self):
        s: Sha256WithEcdsaSigner = self.consumer_signer
        prikey: EccKey = s.key
        pubkey: EccKey = prikey.public_key()
        encoded_text = 'hello'.encode()
        cipher_text = encrypt(pubkey, encoded_text)
        decrypted_text = decrypt(pubkey, cipher_text)
        self.assertEqual(decrypted_text, encoded_text)
