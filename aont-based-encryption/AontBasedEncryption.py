from ctypes import POINTER, c_ubyte, cdll
from ctypes import CDLL, RTLD_GLOBAL
import time

libcrypto = CDLL('./libcrypto.so.1.1', mode=RTLD_GLOBAL)
lib = cdll.LoadLibrary('./bin/libAontBasedEncryption.so')

lib.AontBasedEncryption_Encrypt.restype = POINTER(POINTER(c_ubyte))
lib.AontBasedEncryption_Decrypt.restype = POINTER(c_ubyte)
lib.AontBasedEncryption_AesCbc.restype = POINTER(c_ubyte)

L = 32

class AontBasedEncryption(object):
    def __init__(self):
        self.obj = lib.AontBasedEncryption_new()

    def test(self):
        lib.AontBasedEncryption_Test(self.obj)

    def encrypt(self, ctr, prfKey1, prfKey2, prfKey3, message, n):
        res = lib.AontBasedEncryption_Encrypt(self.obj, ctr, prfKey1, prfKey2, prfKey3, message, len(message), n)
        return bytes(res[0][0:L]), bytes(res[1][0:len(message)+L])

    def decrypt(self, ctr, prfKey1, prfKey2, prfKey3, cipher, iv, n):
        res = lib.AontBasedEncryption_Decrypt(self.obj, ctr, prfKey1, prfKey2, prfKey3, cipher, len(cipher), iv, n)
        return bytes(res[0:len(cipher)-L])

    # for testing only
    def aes_enc(self, m, size, keyBytes):
        res = lib.AontBasedEncryption_AesCbc(self.obj, m, size, keyBytes)
        return bytes(res[0:size])


enc = AontBasedEncryption()


ctr = b'0' * L
prfKey1 = b'1'*L
prfKey2 = b'2'*L
prfKey3 = b'3'*L
# message = b'ABCD'*(64//4)

# 1GB max !
DATA_INPUT_SIZE = 1*1024*1024*1024

fo = open("../data/random_input", "rb+")
message = fo.read(DATA_INPUT_SIZE)
fo.close()

n = len(message)//L
start = time.time()
res = enc.encrypt(ctr, prfKey1, prfKey2, prfKey3, message, n)
print("Encrypted")
print("took: ", time.time() - start)
iv, cipher = res

start = time.time()
msg = enc.decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, iv, n)
print('Decrypted')
print("took: ", time.time() - start)

if msg == message:
    print('Correctly decrypted')

print('-----------------------------------------------')
start = time.time()
c = enc.aes_enc(message, DATA_INPUT_SIZE, 'A'*32)
print('Encrypted (AES)')
print("took: ", time.time() - start)
