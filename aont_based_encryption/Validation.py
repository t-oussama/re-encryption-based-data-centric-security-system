import time

from AontBasedEncryption import AontBasedEncryption

L = 64
enc = AontBasedEncryption(L, False)
print("Generating ctr & prfKeys")
ctr = b'0' * enc.get_block_size()
prfKey1 = b'1'*enc.get_block_size()
prfKey2 = b'2'*enc.get_block_size()
prfKey3 = b'3'*enc.get_block_size()
# # message = b'ABCD'*(64//4)

# Bytes to use
# DATA_INPUT_SIZE = 1*1024*1024*1024
DATA_INPUT_SIZE = 1024

fo = open("../data/random_text_1GB", "rb+")
message = fo.read(DATA_INPUT_SIZE)
fo.close()

print('Encrypting')
res = enc.encrypt(ctr, prfKey1, prfKey2, prfKey3, message)
print('Encrypted')

iv, cipher = res

print('Decrypting ...')
msg = enc.decrypt(ctr, prfKey1, prfKey2, prfKey3, cipher, iv)
print('Decrypted')

if msg == message:
    print('[+] Correctly decrypted')
else:
    print('[!] messages do not match')

# print('-----------------------------------------------')
# c = enc.aes_enc(message, DATA_INPUT_SIZE, 'A'*32)
# print('Encrypted (AES)')


# Re-encryption
newPrfKey1 = b'4'*enc.get_block_size()
newPrfKey2 = b'5'*enc.get_block_size()
newPrfKey3 = b'6'*enc.get_block_size()

print('Creating re-encryption key 1')
key1 = enc.generate_permutation_key(prfKey1, enc.get_block_size()*8)
newKey1 = enc.generate_permutation_key(newPrfKey1, enc.get_block_size()*8)
reEncryptionKey1 = enc.find_conversion_key(key1, newKey1)

print('Creating re-encryption key 2')
key2 = enc.generate_permutation_key(prfKey2, enc.get_block_size()*8)
newKey2 = enc.generate_permutation_key(newPrfKey2, enc.get_block_size()*8)

print('Creating re-encryption key 3')
key3 = enc.generate_permutation_key(prfKey3, len(message)//enc.get_block_size())
newKey3 = enc.generate_permutation_key(newPrfKey3, len(message)//enc.get_block_size())
reEncryptionKey3 = enc.find_conversion_key(key3, newKey3)


print('Keys generated')

print('ReEncrypting ...')
newIv, newCipher = enc.re_encrypt(reEncryptionKey1, key2, newKey2, reEncryptionKey3, iv, cipher)
print('ReEncrypted')

# Verify re-encryption works as expected
# Encrypt with new keys
res = enc.encrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, message)
print("Encrypted with new keys")
iv2, cipher2 = res

print('[*] cipher is same: ', newCipher == cipher2)
print('[*] iv is same: ', iv2 == iv)

msg = enc.decrypt(ctr, newPrfKey1, newPrfKey2, newPrfKey3, newCipher, iv)

print('Decrypted')

if msg == message:
    print('[+] Correctly decrypted')
else:
    print('[!] messages do not match')
