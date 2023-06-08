import json

from simplejson import loads
from common.encryption_engine.EncryptionEngine import EncryptionMeta
from lib.TrustedAuthority import TrustedAuthority
import base64
import flask
from flask import request, jsonify
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import copy
import yaml

with open('config.yaml', 'r') as file:
    try:
        config = yaml.safe_load(file)
    except yaml.YAMLError as e:
        print(e)

app = flask.Flask(__name__)
app.config['DEBUG'] = config['http']['debug']

ta = TrustedAuthority(config['re_encryption'])

## Verifies user permissions on an application level:
#   * R: user can't create new files, but can write to existing ones if owner gives him to associated permission.
#   * W: user can create new files.
#   * A: user can make administrative actions (like adding users).
# Permissions on other files are always determined by their owner, independently from the user's role on the application level
##
def auth(request, operation):
    request.user = request.headers.get('actor')
    timestamp = float(request.headers.get('timestamp'))
    signature = base64.b64decode(request.headers.get('signature').encode('ascii'))
    return ta.auth(request.user, timestamp, signature, operation)

@app.route('/meta', methods=['GET'])
def getPublicKey():
    return jsonify({'publicKey': base64.b64encode(ta.pubKey.export_key()).decode('utf-8')})

@app.route('/users', methods=['POST'])
def addUser():
    if not auth(request, 'A'):
        return {'error': 'User is not authorized'}, 403

    username = request.json['username']
    publickey = base64.b64decode(request.json['key'].encode('ascii'))
    permission = request.json['permission']

    try:
        ta.addUser(username, publickey, permission)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify(request.json), 201

@app.route('/users/<userId>', methods=['DELETE'])
def deleteUser(userId):
    if not auth(request, 'A'):
        return {'error': 'User is not authorized'}, 403

    try:
        ta.delUser(userId)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return {}

@app.route('/worker-nodes', methods=['POST'])
def addWorkerNode():
    try:
        host = request.json['host']
        port = request.json['port']
        nodeId = request.json['nodeId']
        chunkUploadPort = request.json['chunkUploadPort']
        chunkFetchPort = request.json['chunkFetchPort']
        ta.addWorkerNode(nodeId, host, port, chunkUploadPort, chunkFetchPort)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return { 'message': 'Worker node "' + nodeId + '" added successfully.' }

@app.route('/worker-nodes', methods=['GET'])
def getWorkerNodes():
    if not auth(request, 'A'):
        return {'error': 'User is not authorized'}, 403

    try:
        nodes = ta.getWorkerNodes()
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': nodes })

@app.route('/encryption-engine/config', methods=['GET'])
def getEncryptionEngineConfig():
    # if not auth(request, 'A'):
    #     return {'error': 'User is not authorized'}, 403

    try:
        config = ta.getEncryptionEngineConfig()
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': config })

@app.route('/permission-signature', methods=['POST'])
def getOperationPermissionSignature():
    # TODO: implement this properly
    fileId = request.json['fileId']
    chunkId = request.json['chunkId']
    workerNodeIds = request.json['workerNodeIds']
    ciphertextHash = request.json['ciphertextHash']
    operation = request.json['operation']
    size = request.json['size']


    encryptionMeta = loads(base64.b64decode(request.json['encryptionMeta'].encode('utf-8')).decode('utf-8'))
    chunk = ta.getChunk(fileId, chunkId)
    chunk.encryptionMeta = EncryptionMeta(bytes(encryptionMeta['secret'], 'utf-8'), bytes(encryptionMeta['ctr'], 'utf-8'), bytes(encryptionMeta['iv'], 'utf-8'))
    chunk.size = size
    chunk.workerNodeIds = workerNodeIds
    ta.generateReEncryptionKey(fileId, chunkId)

    data = {
        'fileId': fileId,
        'chunkId': chunkId,
        'size': size,
        'workerNodeIds': workerNodeIds,
        'ciphertextHash': ciphertextHash,
        'operation': operation,
    }
    
    h = SHA256.new(bytes(json.dumps(data), 'utf-8'))
    signature = pkcs1_15.new(ta.privKey).sign(h)
    return jsonify({'signature': base64.b64encode(signature).decode()})

@app.route('/files', methods=['POST'])
def createFile():
    if not auth(request, 'W'):
        return {'error': 'User is not authorized'}, 403

    try:
        fileName = request.json['file']['name']
        fileSize = request.json['file']['size']
        filePath = request.json['file']['path']
        readOnlyUsers = request.json['permissions']['r']
        readWriteUsers = request.json['permissions']['w']
        fileMeta = ta.createFile(fileName, fileSize, filePath, readOnlyUsers, readWriteUsers)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': fileMeta })

@app.route('/files', methods=['GET'])
def getFiles():
    if not auth(request, 'R'):
        return {'error': 'User is not authorized'}, 403

    try:
        filesMeta = ta.getFilesMetaData()
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': filesMeta })

@app.route('/files/<fileId>', methods=['GET'])
def getFile(fileId):
    if not auth(request, 'R'):
        return {'error': 'User is not authorized'}, 403

    try:
        data = copy.deepcopy(ta.getFile(fileId))
        usersWithAccess = data.permissions['r'] + data.permissions['w']
        if not request.user in usersWithAccess:
            return {'error': 'You do not have permission to read this file'}, 403
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    h = SHA256.new(bytes(json.dumps({'fileId': fileId}), 'utf-8'))
    signature = pkcs1_15.new(ta.privKey).sign(h)
    # map data chunks from bytes to strings

    for chunkId in data.chunks.keys():
        data.chunks[chunkId].encryptionMeta.secret = data.chunks[chunkId].encryptionMeta.secret.decode()
        data.chunks[chunkId].encryptionMeta.ctr = data.chunks[chunkId].encryptionMeta.ctr.decode()
        data.chunks[chunkId].encryptionMeta.iv = data.chunks[chunkId].encryptionMeta.iv.decode()
        del data.chunks[chunkId].encryptionMeta.rk
        del data.chunks[chunkId].encryptionMeta.newSecret
        ta.generateReEncryptionKey(fileId, chunkId)
    return jsonify({'data': data.toDict(), 'signature': base64.b64encode(signature).decode()})


@app.route('/chunks/state', methods=['POST'])
def setState():
    if not auth(request, 'W'):
        return {'error': 'User is not authorized'}, 403

    try:
        fileId = request.json['fileId']
        chunkId = request.json['chunkId']
        state = request.json['state']
        reEncrypted = ta.updateChunkState(fileId, chunkId, state)
        if reEncrypted:
            print('[+] Chunk reEncrypted')
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'success': True })

@app.route('/files/<fileId>/access/<userId>', methods=['DELETE'])
def revokeUserAccess(fileId, userId):
    if not auth(request, 'W'):
        return {'error': 'User is not authorized'}, 403

    try:
        # check if user making the request can update the file
        data = copy.deepcopy(ta.getFile(fileId))
        usersWithAccess = data.permissions['w']
        if not request.user in usersWithAccess:
            return {'error': 'You do not have permission to update this file'}, 403
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    ta.revokeUserAccess(userId, fileId)
    
    return jsonify({ 'success': True })


app.run(host=config['http']['host'], port=config['http']['port'])