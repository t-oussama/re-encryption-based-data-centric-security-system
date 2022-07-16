import json
from lib.TrustedAuthority import TrustedAuthority
import base64
import flask
from flask import request, jsonify
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

app = flask.Flask(__name__)
app.config["DEBUG"] = True

ta = TrustedAuthority()

def auth(request):
    actor = request.headers.get('actor')
    timestamp = float(request.headers.get('timestamp'))
    signature = base64.b64decode(request.headers.get('signature').encode("ascii"))
    return ta.auth(actor, timestamp, signature, 'A')

@app.route('/meta', methods=['GET'])
def getPublicKey():
    return jsonify({'publicKey': base64.b64encode(ta.pubKey.export_key())})

@app.route('/users', methods=['POST'])
def addUser():
    if not auth(request):
        return {'error': 'User is not authorized'}, 403

    username = request.json['username']
    publickey = base64.b64decode(request.json['key'].encode("ascii"))
    permission = request.json['permission']

    try:
        ta.addUser(username, publickey, permission)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify(request.json), 201

@app.route('/users', methods=['DELETE'])
def deleteUser():
    if not auth(request):
        return {'error': 'User is not authorized'}, 403

    username = request.json['username']

    try:
        ta.delUser(username)
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
        ta.addWorkerNode(nodeId, host, port)
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return { 'message': 'Worker node "' + nodeId + '" added successfully.' }

@app.route('/worker-nodes', methods=['GET'])
def getWorkerNodes():
    if not auth(request):
        return {'error': 'User is not authorized'}, 403

    try:
        nodes = ta.getWorkerNodes()
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': nodes })

@app.route('/encryption-engine/config', methods=['GET'])
def getEncryptionEngineConfig():
    if not auth(request):
        return {'error': 'User is not authorized'}, 403

    try:
        config = ta.getEncryptionEngineConfig()
    except Exception as e:
        print(e)
        return {'error': str(e)}, 400

    return jsonify({ 'data': config })

@app.route('/permission-signature', methods=['GET'])
def getOperationPermissionSignature():
    # TODO: implement this properly
    fileId = request.args.get('fileId')
    chunkId = request.args.get('chunkId')
    workerNodeId = request.args.get('workerNodeId')
    # decryptionKey = request.args.get('decryptionKey')
    ciphertextHash = request.args.get('ciphertextHash')
    operation = request.args.get('operation')

    data = {
        'fileId': fileId,
        'chunkId': chunkId,
        'workerNodeId': workerNodeId,
        'ciphertextHash': ciphertextHash,
        'operation': operation,
    }
    
    h = SHA256.new(bytes(json.dumps(data), 'utf-8'))
    print('bytes', bytes(json.dumps(data), 'utf-8'))
    print('h', h.hexdigest())
    signature = pkcs1_15.new(ta.privKey).sign(h)
    print('signature', signature)
    return jsonify({'signature': base64.b64encode(signature).decode()})

@app.route('/files', methods=['POST'])
def createFile():
    if not auth(request):
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

app.run()