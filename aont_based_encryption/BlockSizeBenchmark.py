import time
import json
import sys

from AontBasedEncryption import AontBasedEncryption

logFile = open('blockSizeBenchmark.log', 'a')

blockSize = int(sys.argv[1])
print(f'*** Encrypting using blocksize {blockSize} ***')

enc = AontBasedEncryption(blockSize)

ctr = b'0' * enc.getBlockSize()
prfKey1 = b'1'*enc.getBlockSize()
prfKey2 = b'2'*enc.getBlockSize()
prfKey3 = b'3'*enc.getBlockSize()
# # message = b'ABCD'*(64//4)

# Bytes to use
# DATA_INPUT_SIZE = 1*1024*1024*1024
DATA_INPUT_SIZE = 512*1024*1024

fo = open("../data/random_text", "rb+")
message = fo.read(DATA_INPUT_SIZE)
fo.close()

logs = { 'blockSize': blockSize }

print('Encrypting')
start = time.time()
res = enc.encrypt(ctr, prfKey1, prfKey2, prfKey3, message)
execTime = time.time() - start
print('Encrypted')
print('Execution time', execTime, '\n\n')
logs['enc'] = execTime

iv, cipher = res

print('Decrypting ...')
start = time.time()
msg = enc.decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, iv)
execTime = time.time() - start
print('Decrypted')
print('Execution time', execTime, '\n\n')
logs['dec'] = execTime

if msg == message:
    print('Correctly decrypted')
else:
    print('messages do not match')

# Re-encryption
start = time.time()
newPrfKey1 = b'4'*enc.getBlockSize()
newPrfKey2 = b'5'*enc.getBlockSize()
newPrfKey3 = b'6'*enc.getBlockSize()

print('Creating re-encryption key 1')
keyStart = time.time()
key1 = enc.generate_permutation_key(prfKey1, enc.getBlockSize()*8)
newKey1 = enc.generate_permutation_key(newPrfKey1, enc.getBlockSize()*8)
reEncryptionKey1 = enc.find_conversion_key(key1, newKey1)
logs['key1Gen'] = time.time() - keyStart

print('Creating re-encryption key 2')
keyStart = time.time()
key2 = enc.generate_permutation_key(prfKey2, enc.getBlockSize()*8)
newKey2 = enc.generate_permutation_key(newPrfKey2, enc.getBlockSize()*8)
logs['key2Gen'] = time.time() - keyStart

print('Creating re-encryption key 3')
keyStart = time.time()
key3 = enc.generate_permutation_key(prfKey3, len(message)//enc.getBlockSize())
newKey3 = enc.generate_permutation_key(newPrfKey3, len(message)//enc.getBlockSize())
reEncryptionKey3 = enc.find_conversion_key(key3, newKey3)
logs['key3Gen'] = time.time() - keyStart

execTime = time.time() - start
print('Keys generated')
print('Execution time', execTime, '\n\n')
logs['keyGen'] = execTime

print('ReEncrypting ...')
start = time.time()
newIv, newCipher = enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, cipher)
execTime = time.time() - start
print('ReEncrypted')
print('Execution time', execTime, '\n\n')
logs['reEnc'] = execTime

# # Verify re-encryption works as expected
# # Encrypt with new keys
# res = enc.encrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, message)
# print("Encrypted with new keys")
# iv2, cipher2 = res

# print('cipher is same: ', newCipher == cipher2)
# print('iv is same: ', iv2 == iv)

msg = enc.decrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, newCipher, iv)

print('Decrypted')

if msg == message:
    print('Correctly decrypted')
else:
    print('messages do not match')

print('-------------------------------------')
print('Results\n', logs)
logFile.write(json.dumps(logs) + '\n')
print('-------------------------------------')

logFile.close()