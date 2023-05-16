from Client import Client
from Logger import Logger
import os
import time

client = Client('user1')
logger = Logger(f'scenario2_{time.time()}')

# create new user
newUserName = 'new_test_user'
client.addUser(newUserName, 'A')

# upload 5MB file
localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_text'
remoteDirectory = '/'
remoteFilename = 'test'
usersWithReadOnly = 'user3'
usersWithReadWrite = f'user1,user2,{newUserName}'

print(f'[i] File size {logger.sizeof_fmt(os.path.getsize(localFilePath))}')
start_time = time.time()
fileId = client.uploadFile(localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite)
exec_duration = time.time() - start_time
print(f"File Upload --- {exec_duration} seconds ---")
logger.logPerformance('file_upload', exec_duration)

# get file
start_time = time.time()
client.downloadFile(fileId)
exec_duration = time.time() - start_time
print(f"File Download --- {exec_duration} seconds ---")
logger.logPerformance('file_download', exec_duration)

# remove access to new user
start_time = time.time()
client.revokeUserAccess(newUserName, fileId)
exec_duration = time.time() - start_time
print(f"Revoking access --- {exec_duration} seconds ---")
logger.logPerformance('revoke_access', exec_duration)

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