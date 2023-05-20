from Client import Client
import os
import time

def sequence(fileSize):
    client = Client('user1', f'performance_test_{fileSize}_{time.time()}')

    # create new user
    newUserName = 'new_test_user'
    client.addUser(newUserName, 'A')

    # upload 5MB file
    localFilePath = f'/home/oussama/Workspace/research/re-encryption/data/random_text_{fileSize}'
    remoteDirectory = '/'
    remoteFilename = f'test_{fileSize}'
    usersWithReadOnly = 'user3'
    usersWithReadWrite = f'user1,user2,{newUserName}'


    print('Uploading file ...')
    fileId = client.uploadFile(localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite)
    print('File Uploaded')

    # get file
    print('Downloading file ...')
    client.downloadFile(fileId)
    print('File Downloaded')

    # remove access to new user
    print('Revoking access ...')
    client.revokeUserAccess(newUserName, fileId)
    print('Access revoked')

    # compare file to source
    diff = os.system(f'diff ./{fileId} {localFilePath}')

    if diff:
        print('[i] Decrypted files do not match !')
        print('[!] Scenario failed')
    else:
        print('[i] Decrypted files match !')
        print('[+] Scenario successful')

    # print('[*] Cleaning up')
    # os.system(f'rm ./{fileId}')
    # os.system(f'rm -r ../WN/data/{fileId}')
    print('[+] DONE')

fileSizes = ['1GB', '2GB', '3GB']
for fileSize in fileSizes:
    sequence(fileSize)