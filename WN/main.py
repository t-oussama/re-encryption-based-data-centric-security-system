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
import yaml

from common.encryption_engine.EncryptionEngine import EncryptionEngine

configFile = 'config.yaml'
if len(sys.argv) > 1:
    configFile = sys.argv[1]

with open(configFile, 'r') as file:
    try:
        config = yaml.safe_load(file)
    except yaml.YAMLError as e:
        print(e)

TA_IP = config['TA']['host']
TA_PORT = config['TA']['port']

Id = uuid.uuid4()
port = config['http']['port']
host = config['http']['host']
chunkUploadPort = config['socket']['uploadPort']
chunkFetchPort = config['socket']['downloadPort']
DATA_STORAGE_DIR = './data'

data = { 'host': host, 'port': port, 'nodeId': str(Id), 'chunkUploadPort': str(chunkUploadPort), 'chunkFetchPort': str(chunkFetchPort) }
response = requests.post('http://' + TA_IP + ':' + str(TA_PORT) + '/worker-nodes', json = data)

# import TA public key
response = requests.get('http://' + TA_IP + ':' + str(TA_PORT) + '/meta')
taPublicKey = RSA.import_key(base64.b64decode(bytes(response.json()['publicKey'], 'utf-8')))
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
    bytes_recd = 0
    while bytes_recd < msgLen:
        data = conn.recv(min(msgLen - bytes_recd, 2048))
        file.write(data)
        bytes_recd = bytes_recd + len(data)
    conn.send(b'1')

def handleChunkFetch(conn):
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

    chunkPath = filePath + '/' + meta['chunkId']
    file = open(chunkPath, 'rb')

    # receive data
    dataLen = os.path.getsize(chunkPath) # TODO: this is a temporary fix for files with double size !!
    bytes_sent = 0
    while bytes_sent < dataLen:
        sentLen = min(dataLen - bytes_sent, 2048)
        data = file.read(sentLen)
        conn.send(data)
        bytes_sent = bytes_sent + sentLen
    conn.recv(1)
    # Inform TA that read is over


uploadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
downloadSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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

def chunkFetchListener():
    try:
        downloadSocket.bind((host, chunkFetchPort))
        downloadSocket.listen()
        while True:
            conn, addr = downloadSocket.accept()
            print('connection created: ', addr)
            thread = threading.Thread(target=handleChunkFetch, args=(conn,))
            uploadThreads.append(thread)
            thread.start()

    except Exception as e:
        print(e)
        exit(1)
    finally:
        downloadSocket.close()

chunkUploadListenerThread = threading.Thread(target=chunkUploadListener)
chunkUploadListenerThread.start()

chunkFetchListenerThread = threading.Thread(target=chunkFetchListener)
chunkFetchListenerThread.start()

app = flask.Flask(__name__)
app.config["DEBUG"] = False

@app.route('/test', methods=['GET'])
def test():
    return True

@app.route('/re-encrypt', methods=['POST'])
def reEncrypt():
    fileId = request.json['fileId']
    chunkId = request.json['chunkId']
    iv = request.json['iv'].encode('utf-8')
    rk = request.json['rk']

    filePath = DATA_STORAGE_DIR + '/' + fileId
    if not os.path.exists(filePath):
        os.mkdir(filePath)
    file = open(filePath + '/' + chunkId, 'rb+')
    ciphertext = file.read()
    _, newCiphertext = encryptionEngine.reEncrypt(ciphertext, rk, iv)
    file.seek(0)
    file.write(newCiphertext)
    file.close()
    return jsonify({ 'success': True })

app.run(port=port)

for uploadThread in uploadThreads:
    uploadThread.join()

uploadSocket.close()
downloadSocket.close()