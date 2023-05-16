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
from common.constants import CHUNK_SIZE, L
from common.encryption_engine.EncryptionEngine import EncryptionEngine
from common.encryption_engine.EncryptionEngine import EncryptionMeta

import socket

class Client:
    def __init__(self, admin):
        USER_KEYS_DIR = '../user_keys'
        
        self.admin = admin
        # Load admin keys
        f = open(f'{USER_KEYS_DIR}/{self.admin}/priv.key','r')
        self.adminPrivKey = RSA.import_key(f.read())
        f = open(f'{USER_KEYS_DIR}/{self.admin}/pub.key','r')
        self.adminPubKey = RSA.import_key(f.read())
        # TODO: enable this again and start using config object in the code
        # # Get encryption engine config
        # timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        # authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        # response = requests.get('http://localhost:5000/encryption-engine/config', headers = authData)
        # config = response.text
        # print(config)
        self.encryptionEngine = EncryptionEngine()

    def getRequestMeta(self, username, key):
        timestamp = time.time()
        # timestamp = time.time() - 50
        h = SHA256.new(bytes(f'{username};{timestamp}', 'utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        return timestamp, signature

    ## Add user
    def addUser(self, username, permission):
        # Generate user keys
        key = RSA.generate(2048)
        publickey = key.publickey()

        ## Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        data = { 'username': username, 'permission': permission, 'key': base64.b64encode(publickey.export_key("PEM")).decode("ascii") }
        return requests.post('http://localhost:5000/users', json = data, headers = authData)

    ## Delete user
    def deleteUser(self, userId):
        ## Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        return requests.delete(f'http://localhost:5000/users/{userId}', headers = authData)
    
    # revoke user access to a file
    def revokeUserAccess(self, userId, fileId):
        ## Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        return requests.delete(f'http://localhost:5000/files/{fileId}/access/{userId}', headers = authData)

    def getWorkerNodes(self):
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get('http://localhost:5000/worker-nodes', headers = authData)
        return response.json()['data']


    def uploadFile(self, localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite):
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

        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.post('http://localhost:5000/files', json = data, headers = authData)
        fileMeta = response.json()['data']
        
        chunksIds = fileMeta['chunks'].keys()
        # Initially all chunks are encrypted with the same key but with different ivs
        encryptionMeta = self.encryptionEngine.genEncryptionMeta()
        print('----------------------------------------------------------------')
        with open(localFilePath, 'rb') as file:
            # for each chunk
            for chunkId in chunksIds:
                # read CHUNK_SIZE bytes from file
                plaintext = file.read(CHUNK_SIZE)
                encryptionMeta, ciphertext = self.encryptionEngine.encrypt(plaintext, encryptionMeta)
                ciphertextHash = SHA256.new(data=ciphertext).digest()
                workersIds = list(map(lambda e: e['id'], fileMeta['chunks'][chunkId]['workerNodeIds']))
                authRequest = {
                    'fileId': fileMeta['fileId'],
                    'chunkId': chunkId,
                    'size': CHUNK_SIZE,
                    'workerNodeIds': workersIds,
                    'encryptionMeta': base64.b64encode(dumps(encryptionMeta.__dict__, ensure_ascii=False).encode('utf-8')).decode(),
                    'ciphertextHash': base64.b64encode(ciphertextHash).decode(),
                    'operation': 'write'
                }
                timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
                authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
                response = requests.post('http://localhost:5000/permission-signature', json = authRequest, headers = authData)
                opSignature = response.json()['signature']
                # TODO: think about solving Man in the middle attacks

                # TODO: use workerId to identify worker url
                ciphertextLen = len(ciphertext)
                del authRequest['encryptionMeta']
                meta = { 'authRequest': authRequest, 'signature': opSignature, 'dataLen': ciphertextLen }
                uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                uploadSocket.connect((fileMeta['chunks'][chunkId]['workerNodeIds'][0]['host'], int(fileMeta['chunks'][chunkId]['workerNodeIds'][0]['chunkUploadPort'])))
                uploadSocket.send(dumps(meta, ensure_ascii=False).encode('utf-8'))
                
                # receive server reply
                response = uploadSocket.recv(1)

                # stream data
                for i in range(0, ciphertextLen, 2048):
                    uploadSocket.send(ciphertext[i:min(ciphertextLen, i+2048)])

                response = uploadSocket.recv(1)
                if response == b'1':
                    print(' [+] Chunk uploaded successfully')

                # Inform the TA that the chunk was created
                # TA can later decide if it should be re-encrypted
                requests.post('http://localhost:5000/chunks/state', json = {'fileId': fileMeta['fileId'], 'chunkId': chunkId, 'state': 'created'}, headers = authData)

            print('[+] File created successfully')
        
        return fileMeta['fileId']

    def listFiles(self):
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get('http://localhost:5000/files', headers = authData)
        filesMeta = response.json()
        for fileMeta in filesMeta['data']:
            print(f"* {fileMeta['path']}{fileMeta['name']}  ({fileMeta['id']})")


    def downloadFile(self, fileId):
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get(f'http://localhost:5000/files/{fileId}', headers = authData)
        responseObject = response.json()
        opSignature = responseObject['signature']
        fileMeta = responseObject['data']
        workerNodes = self.getWorkerNodes()
        outputFile = open(fileId, 'wb')
        for chunkId in fileMeta['chunks'].keys():
            uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            workerNodeId = fileMeta['chunks'][chunkId]['workerNodeIds'][0]
            workerNode = list(filter(lambda element: element['id'] == workerNodeId, workerNodes))[0]
            uploadSocket.connect((workerNode['host'], int(workerNode['chunkFetchPort'])))
            uploadSocket.send(dumps({'authRequest': {'fileId': fileId}, 'signature': opSignature, 'chunkId': chunkId}, ensure_ascii=False).encode('utf-8'))
            bytes_received = 0
            data = b''
            while bytes_received < CHUNK_SIZE+32:
                sentLen = min(CHUNK_SIZE+32 - bytes_received, 2048)
                data += uploadSocket.recv(sentLen)
                bytes_received = bytes_received + sentLen
            # receive server reply
            uploadSocket.send(b'1')

            # Inform the TA that the chunk was read
            # TA can later decide if it should be re-encrypted
            requests.post('http://localhost:5000/chunks/state', json = {'fileId': fileId, 'chunkId': chunkId, 'state': 'read'}, headers = authData)

            ctr = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['ctr'], 'utf-8')
            iv = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['iv'], 'utf-8')
            secret = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['secret'], 'utf-8')
            encryptionMeta = EncryptionMeta(secret, ctr, iv)
            plain = self.encryptionEngine.decrypt(data, encryptionMeta)
            outputFile.write(plain)
        outputFile.close()