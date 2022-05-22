from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from .User import User
import os
import time
import uuid
from common import constants
from common.encryption_engine.EncryptionEngine import EncryptionEngine

USERS_PERMISSIONS_FILE = './authorized_users/users_permissions'
AUTHORIZED_USERS_KEYS_DIR = './authorized_users/keys'
TA_KEYS_DIR = './keys'

class TrustedAuthority:
    def __init__(self):
        # Load keys
        f = open(f'{TA_KEYS_DIR}/priv.key','r')
        self.privKey = RSA.import_key(f.read())
        f = open(f'{TA_KEYS_DIR}/pub.key','r')
        self.pubKey = RSA.import_key(f.read())

        # Load users
        f = open(USERS_PERMISSIONS_FILE)
        usersPermissions = f.readlines()
        f.close()

        self.users = {}
        self.workerNodes = {}
        self.files = {}
        print(f'[+] Loading {len(usersPermissions)} users')
        for userPermissions in usersPermissions:
            username, permission = userPermissions.strip().split(',')
            f = open(AUTHORIZED_USERS_KEYS_DIR + '/' + username + '.key', 'r')
            userKey = RSA.import_key(f.read())
            self.users[username] = User(username, userKey, permission)
            print(f'    [*] Loaded {username} - {permission}')
            f.close()

        self.encryptionEngine = EncryptionEngine()

    def addUser(self, username: str, key: bytes, permission: str):
        if username in self.users.keys():
            raise Exception(f'user "{username}" already exists')

        userKey = RSA.import_key(key)
        self.users[username] = User(username, userKey, permission)
        print(f'[+] Added {username} - {permission}')

    def delUser(self, username: str):
        if not username in self.users.keys():
            raise Exception(f'user "{username}" does not exist')

        print(f'[+] Deleted {username} - {self.users[username].permission}')
        del self.users[username]

    def auth(self, actor, timestamp, signature, operation):
        ## Authenticate
        if not actor in self.users.keys():
            raise Exception(f'Cannot find user {actor}')

        currentTimestamp = time.time()
        h = SHA256.new(bytes(f'{actor};{timestamp}', 'utf-8'))
        try:
            pkcs1_15.new(self.users[actor].pubKey).verify(h, signature)
            print('[+] The signature is valid.')
        except (ValueError, TypeError):
           raise Exception(f'Invalid user signature for {actor}')

        if currentTimestamp - timestamp > 30:
            raise Exception('Timestamp too old')

        ## Authorisation
        if operation == 'A':
            return self.users[actor].permission == 'A'
        if operation == 'W':
            return self.users[actor].permission in ['A', 'W']
        # Everyone who has access can at least read
        return True

    def addWorkerNode(self, nodeId, host, port):
        if nodeId in self.workerNodes.keys():
            raise Exception(f'Node {nodeId} already exists')
        self.workerNodes[nodeId] = { 'host': host, 'port': port }

    def getWorkerNodes(self):
        workerNodesData = []
        for nodeId in self.workerNodes.keys():
            workerNodesData.append({'id': nodeId, 'host': self.workerNodes[nodeId]['host'], 'port': self.workerNodes[nodeId]['port'] })
        return workerNodesData

    # def getEncryptionEngineConfig(self):
    #     return self.encryptionEngine.getSharedConfig()

    # TODO: make this a simple round robin
    def getWorkerNodeForNewFile(self):
        # for now return the first one for the sake of simplicity
        return next(iter(self.workerNodes.keys()))

    def createFile(self, fileName, fileSize, filePath, readOnlyUsers, readWriteUsers):
        fileId = str(uuid.uuid4())
        
        floatChunksCount = fileSize / constants.CHUNK_SIZE
        chunksCount = int(floatChunksCount)
        if chunksCount != floatChunksCount:
            chunksCount += 1
        chunks = {}
        for i in range(0, chunksCount):
            chunkId = str(uuid.uuid4())
            chunks[chunkId] = {
                'workers': [self.getWorkerNodeForNewFile()]
            }
        # TODO: validate readOnly & readWrite users. They must:
        #  * exist in self.users
        #  * not exist in both lists as the same time
        #  * have system write permission to be in readWrite list
        self.files[fileId] = {
            'name': fileName,
            'path': filePath,
            'chunks': chunks,
            'permissions': {
                'r': readOnlyUsers,
                'w': readWriteUsers,
            }
        }

        return {
            'fileId': fileId,
            'chunks': chunks
        }

    def persistState(self):
        ## Cleanup
        # Remove existing users key files
        for userKeyFile in os.listdir(AUTHORIZED_USERS_KEYS_DIR):
            os.remove(f'{AUTHORIZED_USERS_KEYS_DIR}/{userKeyFile}')

        ## Persist
        usersPermissionsFile = open(USERS_PERMISSIONS_FILE, 'w')
        for username in self.users.keys():
            # store username & permissions
            usersPermissionsFile.write(f'{username},{self.users[username].permission}\n')
            
            # store key
            userKeyFileName = AUTHORIZED_USERS_KEYS_DIR + '/' + username + '.key'
            # remove key file if it exists (useful in case some users were removed)
            # persist user's file
            userKeyFile = open(userKeyFileName, 'wb')
            userKeyFile.write(self.users[username].pubKey.export_key('PEM'))
            userKeyFile.close()

        usersPermissionsFile.close()

