import sys
import os

from simplejson import dumps
BASE_DIR = os.path.dirname(__file__)
sys.path.append(f'{BASE_DIR}../common')

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import base64
import requests
import os
from constants import CHUNK_SIZE, L
from encryption_engine.EncryptionEngine import EncryptionEngine

import socket

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
    
    chunksIds = fileMeta['chunks'].keys()
    # Initially all chunks are encrypted with the same key but with different ivs
    encryptionMeta = encryptionEngine.genEncryptionMeta()
    print('----------------------------------------------------------------')
    with open(localFilePath, 'rb') as file:
        start_time = time.time()
        # for each chunk
        for chunkId in chunksIds:
            # read CHUNK_SIZE bytes from file
            plaintext = file.read(CHUNK_SIZE)
            print('CHUNK_SIZE', CHUNK_SIZE)
            encryptionMeta, ciphertext = encryptionEngine.encrypt(plaintext, encryptionMeta)
            ciphertextHash = SHA256.new(data=ciphertext).digest()
            workersIds = list(map(lambda e: e['id'], fileMeta['chunks'][chunkId]['workers']))
            authRequest = {
                'fileId': fileMeta['fileId'],
                'chunkId': chunkId,
                'size': CHUNK_SIZE,
                'workerNodeIds': workersIds,
                'encryptionMeta': base64.b64encode(dumps(encryptionMeta.__dict__).encode('utf-8')).decode(),
                'ciphertextHash': base64.b64encode(ciphertextHash).decode(),
                'operation': 'write'
            }
            timestamp, signature = getRequestMeta(admin, adminPrivKey)
            authData = { 'actor': admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
            response = requests.post('http://localhost:5000/permission-signature', json = authRequest, headers = authData)
            opSignature = response.json()['signature']
            # TODO: think about solving Man in the middle attacks

            # TODO: use workerId to identify worker url
            ciphertextLen = len(ciphertext)
            del authRequest['encryptionMeta']
            meta = { 'authRequest': authRequest, 'signature': opSignature, 'dataLen': ciphertextLen }
            print('sending chunk')
            uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            uploadSocket.connect((fileMeta['chunks'][chunkId]['workers'][0]['host'], int(fileMeta['chunks'][chunkId]['workers'][0]['chunkUploadPort'])))
            uploadSocket.send(dumps(meta).encode('utf-8'))
            
            # receive server reply
            response = uploadSocket.recv(1)

            # stream data
            for i in range(0, ciphertextLen, 2048):
                uploadSocket.send(ciphertext[i:min(ciphertextLen, i+2048)])

            response = uploadSocket.recv(1)
            if response == b'1':
                print('Chunk uploaded successfully')

            # Inform the TA that the chunk was created
            # TA can later decide if it should be re-encrypted
            requests.post('http://localhost:5000/chunks/state', json = {'fileId': fileMeta['fileId'], 'chunkId': chunkId, 'state': 'created'}, headers = authData)

        print('file created successfully')
        print("--- %s seconds ---" % (time.time() - start_time))


cmd = -1

while cmd != '0':
    print('**************************************************************')
    print('** Commands **')
    print('1. Add user')
    print('2. Delete user')
    print('3. Get worker nodes')
    print('4. Upload file')
    print('0. Exit\n')
    cmd = input('-> ')
    if cmd == '1':
        addUser()
    elif cmd == '2':
        deleteUser()
    elif cmd == '3':
        getWorkerNodes()
    elif cmd == '4':
        uploadFile()

ee = EncryptionEngine()
