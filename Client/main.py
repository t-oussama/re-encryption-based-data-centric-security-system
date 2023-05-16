from Client import Client


# admin = input('Enter your username: ')
admin='user1'
client = Client(admin)

def addUser():
    username = input('Username: ')
    permission = input('Permission [R,W,A]: ')
    client.addUser(username, permission)

def deleteUser():
    username = input('Username: ')
    client.deleteUser(username)

def revokeUserAccess():
    username = input('Username: ')
    fileId = input('File id: ')
    client.revokeUserAccess(username, fileId)

def uploadFile():
    # localFilePath = input('Path to local file: ')
    # remoteDirectory = input('Directory: ')
    # remoteFilename = input('File name: ')
    # usersWithReadOnly = input('Comma separated list of users with Read Only access (u1, u2, u3...): ')
    # usersWithReadWrite = input('Comma separated list of users with Read Write access (u1, u2, u3...): ')

    localFilePath = '/home/oussama/Workspace/research/re-encryption/data/random_text'
    remoteDirectory = '/'
    remoteFilename = 'test'
    usersWithReadOnly = 'user3'
    usersWithReadWrite = 'user1,user2'
    client.uploadFile(localFilePath, remoteDirectory, remoteFilename, usersWithReadOnly, usersWithReadWrite)

def downloadFile():
    fileId = input('File id: ')
    client.downloadFile(fileId)

cmd = -1

            # chunk size:      1048576
            # ciphertext len:  1048608
            # chunk file size: 2097216

while cmd != '0':
    print('**************************************************************')
    print('** Commands **')
    print('1. Add user')
    print('2. Delete user')
    print('3. Get worker nodes')
    print('4. Upload file')
    print('5. List files')
    print('6. Download File')
    print('7. Revoke user access to file')
    print('0. Exit\n')
    cmd = input('-> ')
    if cmd == '1':
        addUser()
    elif cmd == '2':
        deleteUser()
    elif cmd == '3':
        client.getWorkerNodes()
    elif cmd == '4':
        uploadFile()
    elif cmd == '5':
        client.listFiles()
    elif cmd == '6':
        downloadFile()
    elif cmd == '7':
        revokeUserAccess()
