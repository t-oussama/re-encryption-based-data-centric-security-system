import requests

class WorkerNode:
    @staticmethod
    def reEncrypt(host, port, fileId, chunkId, rk, iv):
        response = requests.post(f'http://localhost:{port}/re-encrypt', json = {'fileId': fileId, 'chunkId': chunkId, 'rk': rk, 'iv': iv})
        print(response.text)
