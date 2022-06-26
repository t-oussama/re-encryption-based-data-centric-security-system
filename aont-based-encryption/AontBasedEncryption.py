from ctypes import *
from ctypes import CDLL, RTLD_GLOBAL
import time
import copy


libcrypto = CDLL('./libcrypto.so.1.1', mode=RTLD_GLOBAL)
lib = cdll.LoadLibrary('./bin/libAontBasedEncryption.so')

lib.AontBasedEncryption_Encrypt.restype = POINTER(POINTER(c_ubyte))
lib.AontBasedEncryption_Decrypt.restype = POINTER(c_ubyte)
lib.AontBasedEncryption_AesCbc.restype = POINTER(c_ubyte)
lib.AontBasedEncryption_FindConversionKey.restype = POINTER(c_uint)
lib.AontBasedEncryption_ReEncrypt.restype = POINTER(POINTER(c_ubyte))
lib.AontBasedEncryption_GeneratePermutationKey.restype = POINTER(c_uint)

lib.AontBasedEncryption_FindConversionKey.argtypes = [c_void_p, POINTER(c_uint), POINTER(c_uint), c_uint]
lib.AontBasedEncryption_ReEncrypt.argtypes = [c_void_p, POINTER(c_uint), POINTER(c_uint), POINTER(c_uint), POINTER(c_uint), c_void_p, c_void_p, c_uint]

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

    def re_encrypt(self, reEncryptionKey1, originalKey2, newKey2, reEncryptionKey3, iv, cipher, n):
        p_reEncryptionKey1 = (c_uint * len(reEncryptionKey1))(*reEncryptionKey1)
        p_originalKey2 = (c_uint * len(originalKey2))(*originalKey2)
        p_newKey2 = (c_uint * len(newKey2))(*newKey2)
        p_reEncryptionKey3 = (c_uint * len(reEncryptionKey3))(*reEncryptionKey3)
        res = lib.AontBasedEncryption_ReEncrypt(self.obj, p_reEncryptionKey1, p_originalKey2, p_newKey2, p_reEncryptionKey3, iv, cipher, n)
        return bytes(res[0][0:L]), bytes(res[1][0:len(message)+L])

    def find_conversion_key(self, permutaionListA, permutaionListB):
        p_permutaionListA = (c_uint * len(permutaionListA))(*permutaionListA)
        p_permutaionListB = (c_uint * len(permutaionListB))(*permutaionListB)
        res = lib.AontBasedEncryption_FindConversionKey(self.obj, p_permutaionListA, p_permutaionListB, len(permutaionListA))
        return res[0:len(permutaionListA)]
        # return (c_uint * len(permutaionListB))(*res)
        # return list(map(lambda x: c_uint(x).value, res[0:len(permutaionListB)]))

    def generate_permutation_key(self, prfKey, permutationKeyLen):
        res = lib.AontBasedEncryption_GeneratePermutationKey(self.obj, prfKey, permutationKeyLen)
        return res[0:permutationKeyLen]
        # return list(map(lambda x: c_uint(x), res[0:permutationKeyLen]))

    # for testing only
    def aes_enc(self, m, size, keyBytes):
        res = lib.AontBasedEncryption_AesCbc(self.obj, m, size, keyBytes)
        return bytes(res[0:size])


enc = AontBasedEncryption()
# enc.test()
# exit(0)

ctr = b'0' * L
prfKey1 = b'1'*L
prfKey2 = b'2'*L
prfKey3 = b'3'*L
# message = b'ABCD'*(64//4)

# 1GB max !
# DATA_INPUT_SIZE = 1*1024*1024*1024
DATA_INPUT_SIZE = 128*1024*1024

fo = open("../data/random_input", "rb+")
message = fo.read(DATA_INPUT_SIZE)
fo.close()

n = len(message)//L
res = enc.encrypt(ctr, prfKey1, prfKey2, prfKey3, message, n)
print("Encrypted")
iv, cipher = res

# msg = enc.decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, iv, n)
# print('Decrypted')

# if msg == message:
#     print('Correctly decrypted')
# else:
#     print('messages do not match')

# print('-----------------------------------------------')
# c = enc.aes_enc(message, DATA_INPUT_SIZE, 'A'*32)
# print('Encrypted (AES)')


# Re-encryption
newPrfKey1 = b'4'*L
newPrfKey2 = b'5'*L
newPrfKey3 = b'6'*L

key1 = enc.generate_permutation_key(prfKey1, L*8)
key2 = enc.generate_permutation_key(prfKey2, L*8)
key3 = enc.generate_permutation_key(prfKey3, n)

print('Generating new keys')
newKey1 = enc.generate_permutation_key(newPrfKey1, L*8)
newKey2 = enc.generate_permutation_key(newPrfKey2, L*8)
newKey3 = enc.generate_permutation_key(newPrfKey3, n)

print('Creating re-encryption key 1')
reEncryptionKey1 = enc.find_conversion_key(key1, newKey1)
print('Creating re-encryption key 3')

reEncryptionKey3 = enc.find_conversion_key(key3, newKey3)
print('ReEncrypt')

newIv, newCipher = enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, cipher, n)
print('ReEncrypted')

# # Encrypt with new keys
res = enc.encrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, message, n)
print("Encrypted with new keys")
iv2, cipher2 = res

print('cipher is same: ', newCipher == cipher2)
print('iv is same: ', iv2 == iv)

msg = enc.decrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, newCipher, iv, n)

print('Decrypted')

if msg == message:
    print('Correctly decrypted')
else:
    print('messages do not match')