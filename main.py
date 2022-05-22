import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from TA.lib.TrustedAuthorityApi import TrustedAuthorityApi
import time
import base64

def getRequestMeta(username, key):
    timestamp = time.time()
    # timestamp = time.time() - 50
    h = SHA256.new(bytes(f'{username};{timestamp}', 'utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return timestamp, signature


USER_KEYS_DIR = './user_keys'
# Load admin keys
admin = 'user1'
f = open(f'{USER_KEYS_DIR}/{admin}/priv.key','r')
adminPrivKey = RSA.import_key(f.read())
f = open(f'{USER_KEYS_DIR}/{admin}/pub.key','r')
adminPubKey = RSA.import_key(f.read())

## Prepare request meta data
timestamp, signature = getRequestMeta(admin, adminPrivKey)

## Add user
# Generate user keys
ta = TrustedAuthorityApi()
key = RSA.generate(2048)
publickey = key.publickey()
username = 'test_user'
permission = 'R'
# ask TA to add user
# ta.addUser(username, publickey.export_key('PEM'), permission, admin, timestamp, signature)
print(f'"username": "{username}", "key": "{base64.b64encode(publickey.export_key("PEM")).decode("ascii")}", "permission": "{permission}", "actor": "{admin}", "timestamp": {timestamp}, "signature": "{base64.b64encode(signature).decode("ascii")}"')


# ta.delUser(username)
# ta.persistState()

