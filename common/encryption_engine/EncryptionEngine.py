import secrets
import sys
import os

from simplejson import dumps
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
        self.newSecret = None

    def toDict(self):
        return self.__dict__

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

    # def reEncrypt(self, ciphertext, oldSecret, newSecret, iv):
    #     prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(oldSecret)
    #     newPrfKey1, newPrfKey2, newPrfKey3 = self.__generateEncryptionContext__(newSecret)
    #     key1 = self.enc.generate_permutation_key(prfKey1, L*8)
    #     key2 = self.enc.generate_permutation_key(prfKey2, L*8)
    #     key3 = self.enc.generate_permutation_key(prfKey3, len(ciphertext)//L - 1)

    #     newKey1 = self.enc.generate_permutation_key(newPrfKey1, L*8)
    #     newKey2 = self.enc.generate_permutation_key(newPrfKey2, L*8)
    #     newKey3 = self.enc.generate_permutation_key(newPrfKey3, len(ciphertext)//L - 1)

    #     reEncryptionKey1 = self.enc.find_conversion_key(key1, newKey1)
    #     reEncryptionKey3 = self.enc.find_conversion_key(key3, newKey3)
    #     return self.enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, ciphertext)

    def reEncrypt(self, ciphertext, reEncryptionKey, iv):
        reEncryptionKey1 = reEncryptionKey['reEncryptionKey1']
        key2 = reEncryptionKey['key2']
        newKey2 = reEncryptionKey['newKey2']
        reEncryptionKey3 = reEncryptionKey['reEncryptionKey3']
        print('len reEncryptionKey1: ', len(reEncryptionKey1))
        print('len key2: ', len(key2))
        print('len newKey2: ', len(newKey2))
        print('len reEncryptionKey3: ', len(reEncryptionKey3))
        return self.enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, ciphertext)

    def getReEncryptionKey(self, oldSecret, newSecret, ciphertextLen):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(oldSecret)
        newPrfKey1, newPrfKey2, newPrfKey3 = self.__generateEncryptionContext__(newSecret)
        key1 = self.enc.generate_permutation_key(prfKey1, L*8)
        key2 = self.enc.generate_permutation_key(prfKey2, L*8)
        key3 = self.enc.generate_permutation_key(prfKey3, ciphertextLen//L - 1)

        newKey1 = self.enc.generate_permutation_key(newPrfKey1, L*8)
        newKey2 = self.enc.generate_permutation_key(newPrfKey2, L*8)
        newKey3 = self.enc.generate_permutation_key(newPrfKey3, ciphertextLen//L - 1)

        reEncryptionKey1 = self.enc.find_conversion_key(key1, newKey1)
        reEncryptionKey3 = self.enc.find_conversion_key(key3, newKey3)
        return {'reEncryptionKey1': reEncryptionKey1, 'reEncryptionKey3': reEncryptionKey3, 'key2': key2, 'newKey2': newKey2}


if __name__ == '__main__':
    ee = EncryptionEngine()
    meta, c = ee.encrypt(b'a'*L*4, EncryptionMeta( b'0'*L, 'A'*L))
    # msg = ee.decrypt(c, b'0'*L, iv)
    # print(msg)
    rk = ee.getReEncryptionKey(b'0'*L, b'1'*L, len(c))
    newIv, new_c = ee.reEncrypt(c, rk, meta.iv)
    msg = ee.decrypt(new_c, EncryptionMeta( b'1'*L, 'A'*L, meta.iv))
    print(msg)