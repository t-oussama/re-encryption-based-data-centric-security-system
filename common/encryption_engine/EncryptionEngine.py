# from npre import bbs98
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from common.Utils import xor
from common.constants import L
from bitarray import bitarray
from Crypto.Util.Padding import pad

class KeyPair:
    def __init__(self, secretKey: bytes, publicKey: bytes) -> None:
        self.secretKey: bytes = secretKey
        self.publicKey: bytes = publicKey
        self.cypher = None

class EncryptionEngine:
    def __init__(self, config = None) -> None:
        # self.pre = bbs98.PRE()
        pass

    # def genKeyPair(self) -> KeyPair:
    #     secretKey = self.pre.gen_priv(dtype=bytes)
    #     publicKey = self.pre.priv2pub(secretKey)
    #     return KeyPair(secretKey, publicKey)

    # def encrypt(self, message, encryptionKey) -> bytes:
    #     return self.pre.encrypt(encryptionKey, message)

    # def decrypt(self, message, decryptionKey) -> bytes:
    #     return self.pre.decrypt(decryptionKey, message)

    # def getReEncryptionKey(self, originalDecryptionKey, targetDecryptionKey) -> bytes:
    #     return self.pre.rekey(originalDecryptionKey, targetDecryptionKey)

    # def reEncrypt(self, originalCiphertext, reEncryptionkey) -> bytes:
    #     return self.pre.reencrypt(reEncryptionkey, originalCiphertext)
        

    def aontEncryption(self, ctr: list[bytes], m: list[bytes]) -> list[bytes]:
        x = []
        n = len(m)
        mSize = (n*L) # size of m in bytes
        counterMaxBytesCount = (mSize // 256) + 1
        counterMaxBytesCount = min(counterMaxBytesCount, L)
        prefix = ctr[0: L - counterMaxBytesCount]

        self.__initCipher()

        for i in range(0, n):
            block_rand = self.__pseudoRandomFunction(prefix + (i).to_bytes(counterMaxBytesCount, byteorder='little'), L)
            x.append(bytes(xor(m[i], block_rand)))

        h = SHA256.new(data=x[0])
        for i in range(1, n):
            h.update(x[i])
        hashDigest = h.digest()[0:len(self.prfKey)]
        token = xor(self.prfKey, hashDigest)

        result = []
        for i in range(0, n):
            h_i = xor(token, prefix + (i).to_bytes(counterMaxBytesCount, byteorder='little'))
            result.append(xor(x[i], h_i))

        result.append(token)
        return result

    def aontDecryption(self, ctr:list[bytes], c: list[bytes]):
        x = []
        m = []
        n = len(c) - 1
        mSize = (n*L) # size of m in bytes
        counterMaxBytesCount = (mSize // 256) + 1
        prefix = ctr[0:len(ctr) - counterMaxBytesCount]

        token = c[n]

        for i in range(0, n):
            h_i = xor(token, prefix + (i).to_bytes(counterMaxBytesCount, byteorder='little'))
            x.append(xor(c[i], h_i))
        
        h = SHA256.new(data=x[0])
        for i in range(1, n):
            h.update(x[i])
        hashDigest = h.digest()[0:len(self.prfKey)]
        prfKey = xor(token, hashDigest)
        self.__initCipher(prfKey)

        for i in range(0, n):
            block_rand = self.__pseudoRandomFunction(prefix + (i).to_bytes(counterMaxBytesCount, byteorder='little'), L)
            m.append(bytes(xor(x[i], block_rand)))
        
        return m

    def bitsPermutationEncryption(self, permutations: list[int], x: bytes) -> bytes:
        bitArray = bitarray(endian='little')
        bitArray.frombytes(x)
        bitArrayLength = len(bitArray)
        if len(permutations) != bitArrayLength:
            raise Exception(f'Permutations and input bits must have the same length')
        
        result = bitarray(endian='little')
        for i in range(0, bitArrayLength):
            result.append(bitArray[permutations[i]])
        
        return result.tobytes()

    def bitsPermutationDecryption(self, permutations: list[int], x: bytes) -> bytes:
        bitArray = bitarray(endian='little')
        bitArray.frombytes(x)
        bitArrayLength = len(bitArray)
        if len(permutations) != bitArrayLength:
            raise Exception('Permutations and input bits must have the same length')
        
        result = bitarray(bitArrayLength, endian='little')
        for i in range(0, bitArrayLength):
            result[permutations[i]] = bitArray[i]
        
        return result.tobytes()

    def permutationEncryption(self, permutations: list[int], x: list) -> list:
        if len(permutations) != len(x):
            raise Exception('Permutations and input arrays must have the same length')
        
        result = []
        for i in range(0, len(x)):
            result.append(x[permutations[i]])
        return result

    def permutationDecryption(self, permutations: list[int], x: list) -> list:
        if len(permutations) != len(x):
            raise Exception('Permutations and input arrays must have the same length')
        
        result = [0] * len(x)
        for i in range(0, len(x)):
            result[permutations[i]] = x[i]
        return result


    def findConversionKey(self, parmutationListA: list[int], parmutationListB: list[int]):
        n = len(parmutationListA)
        if n != len(parmutationListB):
            raise Exception('Permutations and input arrays must have the same length')

        result = []
        for i in range(0, n):
            for j in range(0, n):
                if parmutationListA[i] == parmutationListB[j]:
                    result[j] = i
                    break
        return result

    def generatePermutationKey(self, prfKey: bytes, n: int):
        self.__initCipher(prfKey)
        key = []
        tmp = []

        for i in range(0, n):
            key.append(i)
            tmp.append(self.__pseudoRandomFunction((i).to_bytes(L, byteorder='little')))

        self.__quickSort(key, tmp, 0, n)
        return key

    def generatePermutationKeys(self, prfKey1 = None, prfKey2 = None, prfKey3 = None, n = None):
        permKey1 = self.generatePermutationKey(prfKey1, L * 8)
        permKey2 = self.generatePermutationKey(prfKey2, L * 8)
        permKey3 = self.generatePermutationKey(prfKey3, n)
        
        return permKey1, permKey2, permKey3

    def encrypt(self, ctr: bytes, prfKey1, prfKey2, prfKey3, m: list[bytes], n: int):
        permKey1, permKey2, permKey3 = self.generatePermutationKeys(prfKey1, prfKey2, prfKey3, n)
        iv = get_random_bytes(L)
        c = []
        n = len(m)

        m1 = self.aontEncryption(ctr, m)
        m2 = self.permutationEncryption(permKey3, m1[0:n])
        
        encryptedToken = self.bitsPermutationEncryption(permKey1, m1[-1])
        encryptedIV = self.bitsPermutationEncryption(permKey2, iv)
        c.append(xor(encryptedToken, encryptedIV))

        for i in range(0, n):
            x = self.bitsPermutationEncryption(permKey1, m2[i])
            y = self.bitsPermutationEncryption(permKey2, c[i]) # c already has an element so on iteration i we are populating c[i+1], so c[i] is the previous value in c
            c.append(xor(x, y))
        
        return iv, c

    def decrypt(self, ctr: bytes, prfKey1, prfKey2, prfKey3, iv: list[bytes], c: list[bytes], n: int):
        permKey1, permKey2, permKey3 = self.generatePermutationKeys(prfKey1, prfKey2, prfKey3, n)
        m2 = [0]*n
        m1 = []
        for i in range(0, n):
            m2[n-i-1] = self.bitsPermutationDecryption(permKey1, xor(c[n-i], self.bitsPermutationEncryption(permKey2, c[n-i-1])))
        
        token = self.bitsPermutationDecryption(permKey1, xor(c[0], self.bitsPermutationEncryption(permKey2, iv)))
        m1 = self.permutationDecryption(permKey3, m2[0:n])
        m1.append(token)
        return self.aontDecryption(ctr, m1)

    def __quickSort(self, key, tmp, start, end):
        if start >= end-1:
            return
        
        q = self.__partition(key, tmp, start, end)
        self.__quickSort(key, tmp, start, q)
        self.__quickSort(key, tmp, q + 1, end)

    def __partition(self, key, tmp, start, end):
        pivot = tmp[end-1]
        i = start
        for j in range(start, end - 1):
            if tmp[j] <= pivot:
                tmp[i], tmp[j] = tmp[j], tmp[i]
                key[i], key[j] = key[j], key[i]
                i += 1
        tmp[i], tmp[end - 1] = tmp[end - 1], tmp[i]
        key[i], key[end - 1] = key[end - 1], key[i]
        return i

    def __initCipher(self, prfKey = None):
        if not prfKey or not len(prfKey):
            prfKey = get_random_bytes(L)
        elif not len(prfKey) == L:
            raise Exception(f'Expected PRF key of size ${L} but found size ${len(prfKey)}')
        self.prfKey = prfKey
        self.cipher = AES.new(prfKey, AES.MODE_ECB)

    def __pseudoRandomFunction(self, seed , length = None):
        if length and length > 128:
            raise Exception(f'Block length cannot exceed 128 when using AES, got length = ${length}')

        ciphertext = self.cipher.encrypt(pad(seed, AES.block_size))
        if length:
            return bytes(ciphertext[0:length])

        return ciphertext