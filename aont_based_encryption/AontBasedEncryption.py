from ctypes import *
from ctypes import CDLL, RTLD_GLOBAL
import os

BASE_DIR = os.path.dirname(__file__)

libcrypto = CDLL(f'{BASE_DIR if len(BASE_DIR) > 0 else "."}/libcrypto.so.1.1', mode=RTLD_GLOBAL)
lib = cdll.LoadLibrary(f'{BASE_DIR if len(BASE_DIR) > 0 else "."}/bin/libAontBasedEncryption.so')

class AontBasedEncryptionType (Structure):
    pass

lib.AontBasedEncryption_Encrypt.restype = POINTER(POINTER(c_ubyte))
lib.AontBasedEncryption_Decrypt.restype = POINTER(c_ubyte)
lib.AontBasedEncryption_FindConversionKey.restype = POINTER(c_uint)
lib.AontBasedEncryption_ReEncrypt.restype = POINTER(POINTER(c_ubyte))
lib.AontBasedEncryption_GeneratePermutationKey.restype = POINTER(c_uint)
lib.AontBasedEncryption_GetBlockSize.restype = c_int
lib.AontBasedEncryption_FindConversionKey.argtypes = [c_void_p, POINTER(c_uint), POINTER(c_uint), c_uint]
lib.AontBasedEncryption_ReEncrypt.argtypes = [c_void_p, POINTER(c_uint), POINTER(c_uint), POINTER(c_uint), POINTER(c_uint), c_void_p, c_void_p, c_uint]
lib.AontBasedEncryption_new.restype = POINTER(AontBasedEncryptionType)
# lib.AontBasedEncryption_new.argtypes = [c_int, bool]

class AontBasedEncryption(object):
    def __init__(self, blockSize, logPerformance):
        self.blockSize = blockSize
        self.obj = lib.AontBasedEncryption_new(self.blockSize, logPerformance)

    def test(self):
        lib.AontBasedEncryption_Test(self.obj)

    def encrypt(self, ctr, prfKey1, prfKey2, prfKey3, message):
        res = lib.AontBasedEncryption_Encrypt(self.obj, ctr, prfKey1, prfKey2, prfKey3, message, len(message), len(message)//self.blockSize)
        return bytes(res[0][0:self.blockSize]), bytes(res[1][0:len(message)+self.blockSize])

    def decrypt(self, ctr, prfKey1, prfKey2, prfKey3, cipher, iv):
        res = lib.AontBasedEncryption_Decrypt(self.obj, ctr, prfKey1, prfKey2, prfKey3, cipher, len(cipher), iv, len(cipher)//self.blockSize - 1)
        return bytes(res[0:len(cipher)-self.blockSize])

    def re_encrypt(self, reEncryptionKey1, originalKey2, newKey2, reEncryptionKey3, iv, cipher):
        p_reEncryptionKey1 = (c_uint * len(reEncryptionKey1))(*reEncryptionKey1)
        p_originalKey2 = (c_uint * len(originalKey2))(*originalKey2)
        p_newKey2 = (c_uint * len(newKey2))(*newKey2)
        p_reEncryptionKey3 = (c_uint * len(reEncryptionKey3))(*reEncryptionKey3)
        res = lib.AontBasedEncryption_ReEncrypt(self.obj, p_reEncryptionKey1, p_originalKey2, p_newKey2, p_reEncryptionKey3, iv, cipher, len(cipher)//self.blockSize - 1)
        return bytes(res[0][0:self.blockSize]), bytes(res[1][0:len(cipher)])

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

    def get_block_size(self):
        return lib.AontBasedEncryption_GetBlockSize(self.obj)

    def validate(self):
        return lib.AontBasedEncryption_Tests(self.blockSize)
    

# aont_enc = AontBasedEncryption(64, False)
# aont_enc.validate()