from Client import Client
import os

client = Client('user1', 'scenario_1')

# upload 5MB file
localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_text'
remoteDirectory = '/'
remoteFilename = 'test'
usersWithReadOnly = 'user3'
usersWithReadWrite = 'user1,user2'
fileId = client.uploadFile(localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite)


# get file
client.downloadFile(fileId)

# compare file to source
diff = os.system(f"diff ./{fileId} {localFilePath}")

if diff:
    print('[i] Decrypted files do not match !')
    print('[!] Scenario failed')
else:
    print('[i] Decrypted files match !')
    print('[+] Scenario successful')

print('[*] Cleaning up')
os.system(f"rm ./{fileId}")
os.system(f"rm -r ../WN/data/{fileId}")
print('[+] DONE')