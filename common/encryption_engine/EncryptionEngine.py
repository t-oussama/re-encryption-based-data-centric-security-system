import secrets
import string
import sys
import os

from simplejson import dumps
BASE_DIR = os.path.dirname(__file__)
sys.path.append(f'{BASE_DIR}/../../aont_based_encryption')

from Crypto.Hash import SHA256
from AontBasedEncryption import AontBasedEncryption

import hashlib

class KeyPair:
    def __init__(self, secretKey: bytes, publicKey: bytes) -> None:
        self.secretKey: bytes = secretKey
        self.publicKey: bytes = publicKey
        self.cypher = None

class EncryptionMeta:
    def __init__(self, secret, ctr, iv = None):
        self.secret = secret
        self.ctr = ctr
        self.iv = iv
        self.newSecret = None
        self.rk = None

    def toDict(self):
        return self.__dict__

class EncryptionEngine:
    def __init__(self, blockSize = 32, logPerformance = False) -> None:
        print('ENCRYPTION_ENGINE::blockSize: ', blockSize)
        self.enc = AontBasedEncryption(blockSize, logPerformance)

    def __generateEncryptionContext__(self, secret):
        prfKey1 = SHA256.new(data=secret).digest()
        prfKey2 = SHA256.new(data=prfKey1).digest()
        prfKey3 = SHA256.new(data=prfKey2).digest()
        return prfKey1, prfKey2, prfKey3

    def genEncryptionMeta(self):
        secret = b''.join(secrets.choice(string.ascii_letters + string.digits).encode() for i in range(self.enc.get_block_size()))
        ctr = b''.join(secrets.choice(string.ascii_letters + string.digits).encode() for i in range(self.enc.get_block_size()))
        return EncryptionMeta(secret, ctr)

    def encrypt(self, message, encryptionMeta):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(encryptionMeta.secret)
        iv, cipher = self.enc.encrypt(encryptionMeta.ctr, prfKey1, prfKey2, prfKey3, message)
        encryptionMeta.iv = iv
        return encryptionMeta, cipher

    def decrypt(self, ciphertext, encryptionMeta):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(encryptionMeta.secret)
        return self.enc.decrypt(encryptionMeta.ctr, prfKey1, prfKey2, prfKey3, ciphertext, encryptionMeta.iv)

    def reEncrypt(self, ciphertext, reEncryptionKey, iv):
        reEncryptionKey1 = reEncryptionKey['reEncryptionKey1']
        key2 = reEncryptionKey['key2']
        newKey2 = reEncryptionKey['newKey2']
        reEncryptionKey3 = reEncryptionKey['reEncryptionKey3']
        return self.enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, ciphertext)

    def getReEncryptionKey(self, oldSecret, newSecret, ciphertextLen):
        prfKey1, prfKey2, prfKey3 = self.__generateEncryptionContext__(oldSecret)
        newPrfKey1, newPrfKey2, newPrfKey3 = self.__generateEncryptionContext__(newSecret)
        key1 = self.enc.generate_permutation_key(prfKey1, self.enc.get_block_size()*8)
        key2 = self.enc.generate_permutation_key(prfKey2, self.enc.get_block_size()*8)
        key3 = self.enc.generate_permutation_key(prfKey3, ciphertextLen//self.enc.get_block_size() - 1)

        newKey1 = self.enc.generate_permutation_key(newPrfKey1, self.enc.get_block_size()*8)
        newKey2 = self.enc.generate_permutation_key(newPrfKey2, self.enc.get_block_size()*8)
        newKey3 = self.enc.generate_permutation_key(newPrfKey3, ciphertextLen//self.enc.get_block_size() - 1)

        reEncryptionKey1 = self.enc.find_conversion_key(key1, newKey1)
        reEncryptionKey3 = self.enc.find_conversion_key(key3, newKey3)
        return {'reEncryptionKey1': reEncryptionKey1, 'reEncryptionKey3': reEncryptionKey3, 'key2': key2, 'newKey2': newKey2}

    def getBlockSize(self):
        return self.enc.get_block_size()
