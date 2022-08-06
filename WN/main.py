import base64
import flask
from flask import request, jsonify
import sys
import uuid
import requests
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import json
from Crypto.PublicKey import RSA

import os
import socket
import threading

from common.encryption_engine.EncryptionEngine import EncryptionEngine

TA_IP = 'localhost'
TA_PORT = 5000

Id = uuid.uuid4()
port = 8080
chunkUploadPort = 3000
DATA_STORAGE_DIR = './data'

if len(sys.argv) > 1:
    port = int(sys.argv[1])
host = 'localhost'
if len(sys.argv) > 2:
    host = sys.argv[2]
data = { 'host': host, 'port': port, 'nodeId': str(Id), 'chunkUploadPort': str(chunkUploadPort) }
response = requests.post('http://' + TA_IP + ':' + str(TA_PORT) + '/worker-nodes', json = data)
print(response.text)

# import TA public key
response = requests.get('http://' + TA_IP + ':' + str(TA_PORT) + '/meta')
taPublicKey = RSA.import_key(base64.b64decode(response.json()['publicKey']))
uploadThreads = []


encryptionEngine = EncryptionEngine()

def handleChunkWrite(conn):
    metaBytes = conn.recv(1024)
    meta = json.loads(metaBytes)

    signature = bytes(base64.b64decode(meta['signature']))
    authRequestHash = SHA256.new(bytes(json.dumps(meta['authRequest']), 'utf-8'))

    # TODO: error handling can be added for when signatures don't match
    pkcs1_15.new(taPublicKey).verify(authRequestHash, signature)
    
    # prepare output file
    filePath = DATA_STORAGE_DIR + '/' + meta['authRequest']['fileId']
    if not os.path.exists(filePath):
        os.mkdir(filePath)
    file = open(filePath + '/' + meta['authRequest']['chunkId'], 'wb')

    # send reply to inform that verification was successful
    conn.send(b'1')

    # receive data
    msgLen = int(meta['dataLen'])
    print('msgLen', msgLen)
    bytes_recd = 0
    while bytes_recd < msgLen:
        data = conn.recv(min(msgLen - bytes_recd, 2048))
        file.write(data)
        bytes_recd = bytes_recd + len(data)
    conn.send(b'1')
    print('wrote: ', bytes_recd)

uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
def chunkUploadListener():
    try:
        uploadSocket.bind((host, chunkUploadPort))
        uploadSocket.listen()
        while True:
            conn, addr = uploadSocket.accept()
            print('connection created: ', addr)
            thread = threading.Thread(target=handleChunkWrite, args=(conn,))
            uploadThreads.append(thread)
            thread.start()

    except Exception as e:
        print(e)
        exit(1)
    finally:
        uploadSocket.close()

chunkUploadListenerThread = threading.Thread(target=chunkUploadListener)
chunkUploadListenerThread.start()

app = flask.Flask(__name__)
app.config["DEBUG"] = False

@app.route('/test', methods=['GET'])
def test():
    return True

@app.route('/re-encrypt', methods=['POST'])
def reEncrypt():
    print('RE-ENCRYPTING')
    fileId = request.json['fileId']
    chunkId = request.json['chunkId']
    iv = request.json['iv']
    rk = request.json['rk']

    filePath = DATA_STORAGE_DIR + '/' + fileId
    if not os.path.exists(filePath):
        os.mkdir(filePath)
    file = open(filePath + '/' + chunkId, 'rb+')
    ciphertext = file.read()
    print('len: ', len(ciphertext))
    print(len(iv))
    _, newCiphertext = encryptionEngine.reEncrypt(ciphertext, rk, iv)
    file.write(newCiphertext)
    file.close()
    return jsonify({ 'success': True })

app.run(port=port)

for uploadThread in uploadThreads:
    uploadThread.join()

uploadSocket.close()