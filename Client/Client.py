import sys
import os

from simplejson import dumps, loads
from Logger import Logger

BASE_DIR = os.path.dirname(__file__)
sys.path.append(f'{BASE_DIR}../common')

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import time
import base64
import requests
import os
from common.constants import CHUNK_SIZE
from common.encryption_engine.EncryptionEngine import EncryptionEngine
from common.encryption_engine.EncryptionEngine import EncryptionMeta

import socket

class Client:
    def __init__(self, admin, logFileName = 'default'):
        USER_KEYS_DIR = '../user_keys'
        
        self.admin = admin
        # Load admin keys
        f = open(f'{USER_KEYS_DIR}/{self.admin}/priv.key','r')
        self.adminPrivKey = RSA.import_key(f.read())
        f.close()
        f = open(f'{USER_KEYS_DIR}/{self.admin}/pub.key','r')
        self.adminPubKey = RSA.import_key(f.read())
        f.close()
        # Get encryption engine config
        response = requests.get('http://localhost:5000/encryption-engine/config') #, headers = authData)
        self.encryptionEngineConfig = loads(response.text)['data']
        self.encryptionEngine = EncryptionEngine(self.encryptionEngineConfig['blockSize'], self.encryptionEngineConfig['logPerformance'])
        self.logger = Logger(logFileName)

    def getRequestMeta(self, username, key):
        timestamp = time.time()
        h = SHA256.new(bytes(f'{username};{timestamp}', 'utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        return timestamp, signature

    # Add user
    def addUser(self, username, permission):
        # Generate user keys
        key = RSA.generate(2048)
        publickey = key.publickey()

        # Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        data = { 'username': username, 'permission': permission, 'key': base64.b64encode(publickey.export_key("PEM")).decode("ascii") }
        return requests.post('http://localhost:5000/users', json = data, headers = authData)

    # Delete user
    def deleteUser(self, userId):
        # Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        return requests.delete(f'http://localhost:5000/users/{userId}', headers = authData)
    
    # revoke user access to a file
    def revokeUserAccess(self, userId, fileId):
        startTime = time.time()
        # Prepare request meta data
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        res = requests.delete(f'http://localhost:5000/files/{fileId}/access/{userId}', headers = authData)
        self.logger.logPerformance('revoke_access::total', startTime, time.time())
        return res

    def getWorkerNodes(self):
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get('http://localhost:5000/worker-nodes', headers = authData)
        return response.json()['data']


    def uploadFile(self, localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite):
        uploadStartTime = time.time()
        metaCreationStartTime = time.time()
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
        metaCreationEndTime = time.time()
        
        chunksIds = fileMeta['chunks'].keys()
        # Initially all chunks are encrypted with the same key but with different ivs
        encryptionMeta = self.encryptionEngine.genEncryptionMeta()
        chunkTimes = {
            'fileRead': {},
            'encryption': {},
            'hash': {},
            'opSignatureGen': {},
            'uploadOpSigVerification': {},
            'upload': {},
            'taStateUpdate': {},
        }
        with open(localFilePath, 'rb') as file:
            # for each chunk
            for chunkId in chunksIds:
                # read CHUNK_SIZE bytes from file
                chunkTimes['fileRead'][chunkId] = {'start': time.time()}
                plaintext = file.read(CHUNK_SIZE)
                chunkTimes['fileRead'][chunkId]['end'] = time.time()

                chunkTimes['encryption'][chunkId] = {'start': time.time()}
                encryptionMeta, ciphertext = self.encryptionEngine.encrypt(plaintext, encryptionMeta)
                chunkTimes['encryption'][chunkId]['end'] = time.time()
                
                chunkTimes['hash'][chunkId] = {'start': time.time()}
                ciphertextHash = SHA256.new(data=ciphertext).digest()
                chunkTimes['hash'][chunkId]['end'] = time.time()

                chunkTimes['opSignatureGen'][chunkId] = {'start': time.time()}
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
                chunkTimes['opSignatureGen'][chunkId]['end'] = time.time()
                # TODO: think about solving Man in the middle attacks

                # TODO: use workerId to identify worker url
                chunkTimes['uploadOpSigVerification'][chunkId] = {'start': time.time()}
                ciphertextLen = len(ciphertext)
                del authRequest['encryptionMeta']
                meta = { 'authRequest': authRequest, 'signature': opSignature, 'dataLen': ciphertextLen }
                uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                uploadSocket.connect((fileMeta['chunks'][chunkId]['workerNodeIds'][0]['host'], int(fileMeta['chunks'][chunkId]['workerNodeIds'][0]['chunkUploadPort'])))
                uploadSocket.send(dumps(meta, ensure_ascii=False).encode('utf-8'))
                
                # receive server reply about auth check verification
                # TODO: handle the different cases of WN reply
                response = uploadSocket.recv(1)
                chunkTimes['uploadOpSigVerification'][chunkId]['end'] = time.time()

                # stream data
                chunkTimes['upload'][chunkId] = {'start': time.time()}
                for i in range(0, ciphertextLen, 2048):
                    uploadSocket.send(ciphertext[i:min(ciphertextLen, i+2048)])

                response = uploadSocket.recv(1)
                if response != b'1':
                    print(' [!] Unexpected error. Exiting ...')
                    exit(1)
                chunkTimes['upload'][chunkId]['end'] = time.time()

                # Inform the TA that the chunk was created
                # TA can later decide if it should be re-encrypted
                chunkTimes['taStateUpdate'][chunkId] = {'start': time.time()}
                requests.post('http://localhost:5000/chunks/state', json = {'fileId': fileMeta['fileId'], 'chunkId': chunkId, 'state': 'created'}, headers = authData)
                chunkTimes['taStateUpdate'][chunkId]['end'] = time.time()

            print('[+] File created successfully')
        
        # performance logs
        self.logger.logPerformance('upload::total', uploadStartTime, time.time())
        self.logger.logPerformance('upload::metaCreation', metaCreationStartTime, metaCreationEndTime)
        for key in chunkTimes.keys():
            for chunkId in chunkTimes[key].keys():
                self.logger.logPerformance(f'upload::{key}::{chunkId}', chunkTimes[key][chunkId]['start'], chunkTimes[key][chunkId]['end'])

        return fileMeta['fileId']

    def listFiles(self):
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get('http://localhost:5000/files', headers = authData)
        filesMeta = response.json()
        for fileMeta in filesMeta['data']:
            print(f"* {fileMeta['path']}{fileMeta['name']}  ({fileMeta['id']})")


    def downloadFile(self, fileId):
        # wait until file is clean
        waitFileCleanStartTime = time.time()
        isClean = False
        while not isClean:
            timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
            authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
            response = requests.get(f'http://localhost:5000/files/{fileId}/clean', headers = authData)
            responseObject = response.json()
            isClean = responseObject['data']['clean']
        waitFileCleanEndTime = time.time()

        downloadStartTime = time.time()
        chunkTimes = {
            'chunkDownload': {},
            'taStateUpdate': {},
            'chunkDecryption': {},
            'fileWrite': {},
        }

        fetchFileMetaStartTime = time.time()
        timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
        authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
        response = requests.get(f'http://localhost:5000/files/{fileId}', headers = authData)
        responseObject = response.json()
        opSignature = responseObject['signature'] # TODO: check if this is actually working
        fileMeta = responseObject['data']
        fetchFileMetaEndTime = time.time()

        fetchWorkerNodesStartTime = time.time()
        workerNodes = self.getWorkerNodes()
        fetchWorkerNodesEndTime = time.time()
        outputFile = open(f'./data/{fileId}', 'wb')
        for chunkId in fileMeta['chunks'].keys():
            chunkTimes['chunkDownload'][chunkId] = {'start': time.time()}
            downloadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            workerNodeId = fileMeta['chunks'][chunkId]['workerNodeIds'][0]
            workerNode = list(filter(lambda element: element['id'] == workerNodeId, workerNodes))[0]
            downloadSocket.connect((workerNode['host'], int(workerNode['chunkFetchPort'])))
            downloadSocket.send(dumps({'authRequest': {'fileId': fileId}, 'signature': opSignature, 'chunkId': chunkId}, ensure_ascii=False).encode('utf-8'))
            bytes_received = 0
            data = b''
            while bytes_received < CHUNK_SIZE+self.encryptionEngineConfig['blockSize']:
                sentLen = min(CHUNK_SIZE+self.encryptionEngineConfig['blockSize'] - bytes_received, 2048)
                data += downloadSocket.recv(sentLen)
                bytes_received = bytes_received + sentLen
            # send feedback to server
            downloadSocket.send(b'1')
            chunkTimes['chunkDownload'][chunkId]['end'] = time.time()

            # Inform the TA that the chunk was read
            # TA can later decide if it should be re-encrypted
            chunkTimes['taStateUpdate'][chunkId] = {'start': time.time()}
            timestamp, signature = self.getRequestMeta(self.admin, self.adminPrivKey)
            authData = { 'actor': self.admin, 'timestamp': str(timestamp), 'signature': base64.b64encode(signature).decode("ascii") }
            requests.post('http://localhost:5000/chunks/state', json = {'fileId': fileId, 'chunkId': chunkId, 'state': 'read'}, headers = authData)
            chunkTimes['taStateUpdate'][chunkId]['end'] = time.time()

            chunkTimes['chunkDecryption'][chunkId] = {'start': time.time()}
            ctr = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['ctr'], 'utf-8')
            iv = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['iv'], 'utf-8')
            secret = bytes(fileMeta['chunks'][chunkId]['encryptionMeta']['secret'], 'utf-8')
            encryptionMeta = EncryptionMeta(secret, ctr, iv)
            plain = self.encryptionEngine.decrypt(data, encryptionMeta)
            chunkTimes['chunkDecryption'][chunkId]['end'] = time.time()

            chunkTimes['fileWrite'][chunkId] = {'start': time.time()}
            outputFile.write(plain)
            chunkTimes['fileWrite'][chunkId]['end'] = time.time()
        outputFile.close()
        # TODO: This is to check if some time is wasted on file close

        # performance logs
        self.logger.logPerformance('download::waitFileClean', waitFileCleanStartTime, waitFileCleanEndTime)
        self.logger.logPerformance('download::total', downloadStartTime, time.time())
        self.logger.logPerformance('download::fileMetaFetch', fetchFileMetaStartTime, fetchFileMetaEndTime)
        self.logger.logPerformance('download::fetchWorkerNodes', fetchWorkerNodesStartTime, fetchWorkerNodesEndTime)
        for key in chunkTimes.keys():
            for chunkId in chunkTimes[key].keys():
                self.logger.logPerformance(f'download::{key}::{chunkId}', chunkTimes[key][chunkId]['start'], chunkTimes[key][chunkId]['end'])