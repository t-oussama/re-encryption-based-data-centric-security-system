import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random

random_generator = Random.new().read
key = RSA.generate(2048, random_generator)

publickey = key.publickey()

print('Generate key pair')

fPriv = open ('priv.key', 'wb')
fPriv.write(key.export_key('PEM'))
fPriv.close()

fPub = open ('pub.key', 'wb')
fPub.write(publickey.export_key('PEM'))
fPub.close()
