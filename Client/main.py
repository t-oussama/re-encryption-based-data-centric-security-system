from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import base64
import requests
import os
from common.constants import CHUNK_SIZE, L
from common.encryption_engine.EncryptionEngine import EncryptionEngine

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def getRequestMeta(username, key):
    timestamp = time.time()
    # timestamp = time.time() - 50
    h = SHA256.new(bytes(f'{username};{timestamp}', 'utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return timestamp, signature


USER_KEYS_DIR = '../user_keys'
# Load admin keys
# admin = input('Enter your username: ')
admin='user1'
f = open(f'{USER_KEYS_DIR}/{admin}/priv.key','r')
adminPrivKey = RSA.import_key(f.read())
f = open(f'{USER_KEYS_DIR}/{admin}/pub.key','r')
adminPubKey = RSA.import_key(f.read())
# # Get encryption engine config
# timestamp, signature = getRequestMeta(admin, adminPrivKey)
# authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
# response = requests.get('http://localhost:5000/encryption-engine/config', headers = authData)
# config = response.text
# print(config)
encryptionEngine = EncryptionEngine()

## Add user
def addUser():
    # Generate user keys
    key = RSA.generate(2048)
    publickey = key.publickey()
    username = input('Username: ')
    permission = input('Permission [R,W,A]: ')

    ## Prepare request meta data
    timestamp, signature = getRequestMeta(admin, adminPrivKey)
    authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
    data = { 'username': username, 'permission': permission, 'key': base64.b64encode(publickey.export_key("PEM")).decode("ascii") }
    response = requests.post('http://localhost:5000/users', json = data, headers = authData)
    print(response.text)

## Delete user
def deleteUser():
    username = input('Username: ')
    ## Prepare request meta data
    timestamp, signature = getRequestMeta(admin, adminPrivKey)
    authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
    data = { 'username': username }
    response = requests.delete('http://localhost:5000/users', json = data, headers = authData)
    print(response.text)

def getWorkerNodes():
    timestamp, signature = getRequestMeta(admin, adminPrivKey)
    authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
    response = requests.get('http://localhost:5000/worker-nodes', headers = authData)
    print(response.text)


def uploadFile():
    # localFilePath = input('Path to local file: ')
    # remoteDirectory = input('Directory: ')
    # remoteFilename = input('File name: ')
    # usersWithReadOnly = input('Comma separated list of users with Read Only access (u1, u2, u3...): ')
    # usersWithReadWrite = input('Comma separated list of users with Read Write access (u1, u2, u3...): ')

    localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_input'
    remoteDirectory = '/'
    remoteFilename = 'test'
    usersWithReadOnly = 'user3'
    usersWithReadWrite = 'user1,user2'

    usersWithReadOnly = list(map(lambda e: e.strip(), usersWithReadOnly.split(',')))
    usersWithReadWrite = list(map(lambda e: e.strip(), usersWithReadWrite.split(',')))


    fileSize = os.path.getsize(localFilePath)

    data = {
        'file': {
            'name': remoteFilename,
            'path': remoteDirectory,
            'size': fileSize,
        },
        'permissions': {
            'r': usersWithReadOnly,
            'w': usersWithReadWrite
        }
    }

    timestamp, signature = getRequestMeta(admin, adminPrivKey)
    authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
    response = requests.post('http://localhost:5000/files', json = data, headers = authData)
    fileMeta = response.json()['data']
    print(fileMeta)
    
    chunksCount = len(fileMeta['chunks'].keys())
    print('----------------------------------------------------------------')
    print('----------------------------------------------------------------')
    totalSize = 0
    with open(localFilePath, 'rb') as file:
        # for each chunk
        for i in range(0, chunksCount):
            # read CHUNK_SIZE bytes from file
            plaintext = file.read(CHUNK_SIZE)
            keyPair = encryptionEngine.genKeyPair()
            ciphertext = encryptionEngine.encrypt(plaintext, keyPair.publicKey)
            # print(ciphertext)
            print(len(ciphertext))
            totalSize += len(ciphertext)
            print('*******************************************')
            # return
    

# cmd = -1

# while cmd != '0':
#     print('**************************************************************')
#     print('** Commands **')
#     print('1. Add user')
#     print('2. Delete user')
#     print('3. Get worker nodes')
#     print('4. Upload file')
#     print('0. Exit\n')
#     cmd = input('-> ')
#     if cmd == '1':
#         addUser()
#     elif cmd == '2':
#         deleteUser()
#     elif cmd == '3':
#         getWorkerNodes()
#     elif cmd == '4':
#         uploadFile()

# ee = EncryptionEngine()
# c = ee.aontEncryption(b'i'*16, [b'a'*16, b'b'*16, b'c'*16])
# m = ee.aontDecryption(b'i'*16, c)
# assert(m[0] == b'a'*16)
# assert(m[1] == b'b'*16)
# assert(m[2] == b'c'*16)
# print('[+] aont works as expected')

# permutationInput = []
# for i in range(0, 200):
#     permutationInput.append(i)

# key = ee.generatePermutationKey(b'a'*16, 200)

# c = ee.permutationEncryption(key, permutationInput)
# m = ee.permutationDecryption(key, c)
# for i in range(0, 200):
#     assert(m[i] == i)
# print('[+] permutation enc/dec works as expected')

# ctr = b'xyz_'*4
# m = b'12345678'*16
# mList = []
# n = len(m)//L
# for i in range(0, n):
#     mList.append(bytes(m[i * L: (i+1) * L]))

# iv, c = ee.encrypt(ctr, b'1234'*4, b'5678'*4, b'9101'*4, mList, n)
# m = ee.decrypt(ctr, b'1234'*4, b'5678'*4, b'9101'*4, iv, c, n)

# assert(len(mList) == len(m))
# for i in range(0, len(mList)):
#     assert(m[i] == mList[i])

## AONT based
start_time = time.time()
ee = EncryptionEngine()
localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_input'
with open(localFilePath, 'rb') as file:
    totalSize = 0
    ctr = b'xyz_'*4

    fileSize = os.path.getsize(localFilePath)
    chunksCount = fileSize // CHUNK_SIZE

    # for each chunk
    for i in range(0, chunksCount):
        # read CHUNK_SIZE bytes from file
        plaintext = file.read(CHUNK_SIZE)
        n = len(plaintext)//L
        mList = []
        for i in range(0, n):
            mList.append(bytes(plaintext[i * L: (i+1) * L]))

        iv, ciphertext = ee.encrypt(ctr, b'1234'*4, b'5678'*4, b'9101'*4, mList, n)

        totalSize += len(ciphertext)
        print("--- %s seconds ---" % (time.time() - start_time))
        print('*******************************************')



## AES
# start_time = time.time()
# ee = EncryptionEngine()
# localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_input'
# with open(localFilePath, 'rb') as file:

#     fileSize = os.path.getsize(localFilePath)
#     chunksCount = fileSize // CHUNK_SIZE

#     key = get_random_bytes(16)
#     cipher = AES.new(key, AES.MODE_CBC)
#     # for each chunk
#     for i in range(0, chunksCount):
#         # read CHUNK_SIZE bytes from file
#         plaintext = file.read(CHUNK_SIZE)
#         ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))

#         print("--- %s seconds ---" % (time.time() - start_time))
#         print('*******************************************')