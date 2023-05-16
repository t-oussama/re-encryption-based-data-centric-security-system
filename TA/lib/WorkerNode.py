import requests

class WorkerNode:
    @staticmethod
    def reEncrypt(host, port, fileId, chunkId, rk, iv):
        return requests.post(f'http://{host}:{port}/re-encrypt', json = {'fileId': fileId, 'chunkId': chunkId, 'rk': rk, 'iv': iv})

