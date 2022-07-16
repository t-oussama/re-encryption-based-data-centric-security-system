import secrets
import sys
import os
BASE_DIR = os.path.dirname(__file__)
sys.path.append(f'{BASE_DIR}/../../aont_based_encryption')

from Crypto.Hash import SHA256
from AontBasedEncryption import AontBasedEncryption
L = 32

class KeyPair:
    def __init__(self, secretKey: bytes, publicKey: bytes) -> None:
        self.secretKey: bytes = secretKey
        self.publicKey: bytes = publicKey
        self.cypher = None


# key1 = enc.generate_permutation_key(prfKey1, L*8)
# key2 = enc.generate_permutation_key(prfKey2, L*8)
# key3 = enc.generate_permutation_key(prfKey3, n)
class EncryptionMeta:
    def __init__(self, secret, ctr, iv = None):
        self.secret = secret
        self.ctr = ctr
        self.iv = iv
class EncryptionEngine:
    def __init__(self, config = None) -> None:
        self.enc = AontBasedEncryption()

    def __generateEncryptionContext__(self, secret):
        prfKey1 = SHA256.new(data=secret).digest()
        prfKey2 = SHA256.new(data=prfKey1).digest()
        prfKey3 = SHA256.new(data=prfKey2).digest()
        return prfKey1, prfKey2, prfKey3

    def genEncryptionMeta(self):
        secret = b'0'*L
        ctr = b'A'*L
        return EncryptionMeta(secret, ctr)

    def encrypt(self, message, encryptionMeta):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(encryptionMeta.secret)
        iv, cipher = self.enc.encrypt(encryptionMeta.ctr, prfKey1, prfKey2, prfKey3, message)
        encryptionMeta.iv = iv
        return encryptionMeta, cipher

    def decrypt(self, ciphertext, encryptionMeta):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(encryptionMeta.secret)
        return self.enc.decrypt(encryptionMeta.ctr, prfKey1, prfKey2, prfKey3, ciphertext, encryptionMeta.iv)

    def reEncrypt(self, ciphertext, oldSecret, newSecret, iv):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(oldSecret)
        newPrfKey1, newPrfKey2, newPrfKey3 = self.__generateEncryptionContext__(newSecret)
        key1 = self.enc.generate_permutation_key(prfKey1, L*8)
        key2 = self.enc.generate_permutation_key(prfKey2, L*8)
        key3 = self.enc.generate_permutation_key(prfKey3, len(ciphertext)//L - 1)

        newKey1 = self.enc.generate_permutation_key(newPrfKey1, L*8)
        newKey2 = self.enc.generate_permutation_key(newPrfKey2, L*8)
        newKey3 = self.enc.generate_permutation_key(newPrfKey3, len(ciphertext)//L - 1)

        reEncryptionKey1 = self.enc.find_conversion_key(key1, newKey1)
        reEncryptionKey3 = self.enc.find_conversion_key(key3, newKey3)
        return self.enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, ciphertext)


if __name__ == '__main__':
    ee = EncryptionEngine()
    iv, c = ee.encrypt(b'a'*L*4, {'secret': b'0'*L, 'ctr': 'A'*L})
    # msg = ee.decrypt(c, b'0'*L, iv)
    # print(msg)
    newIv, new_c = ee.reEncrypt(c, b'0'*L, b'1'*L, iv)
    msg = ee.decrypt(new_c, {'secret': b'1'*L, 'ctr': 'A'*L, 'iv': iv})
    print(msg)