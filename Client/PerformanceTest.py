from Client import Client
import os
import sys
import traceback 

fileSizes = ['5MB', '500MB', '1GB']
# fileSizes = ['1GB', '2GB']

logFileDir = ''
if len(sys.argv) > 1:
    logFileDir = sys.argv[1]

def sequence(fileSize):
    client = Client('user1', f'{logFileDir}/performance_test_{fileSize}')

    # create new user
    newUserName = 'new_test_user'
    client.addUser(newUserName, 'A')

    # upload file
    localFilePath = f'../data/random_text_{fileSize}'
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
    diff = os.system(f'diff ./data/{fileId} {localFilePath}')

    if diff:
        print('[i] Decrypted files do not match !')
        print('[!] Scenario failed')
    else:
        print('[i] Decrypted files match !')
        print('[+] Scenario successful')

    print('[*] Cleaning up')
    os.system(f'rm ./data/{fileId}')
    os.system(f'rm -r ../WN/data/{fileId}')
    print('[+] DONE')

for fileSize in fileSizes:
    print(f'[i] File Size: {fileSize}')
    try:
        sequence(fileSize)
    except Exception as e:
        print('[!] ERROR')
        print(e);
        print('Traceback:')
        print(traceback.print_exception(*sys.exc_info()))
    print('\n\n')