from datetime import datetime
from threading import Timer

from common.ChunkMeta import ChunkMeta
from .WorkerNode import WorkerNode
from threading import Thread

class Scheduler:
    def __init__(self, config, encryptionEngine, workerNodes, reEncryptionKeyGenThreads):
        self.config = config
        self.encryptionEngine = encryptionEngine
        self.workerNodes = workerNodes
        self.reEncryptionKeyGenThreads = reEncryptionKeyGenThreads
        self.threads = []

    def _reEncrypt(self, fileId, chunk: ChunkMeta):
        # wait until the reEncryption key generation thread is done
        chunk.dirty = True
        self.reEncryptionKeyGenThreads[fileId.decode('utf-8')][chunk.id].join()
        workerNode = self.workerNodes[chunk.workerNodeIds[0]]
        chunk.encryptionMeta.secret = chunk.encryptionMeta.newSecret
        WorkerNode.reEncrypt(workerNode['host'], workerNode['port'], fileId, chunk.id, chunk.encryptionMeta.rk, chunk.encryptionMeta.iv)
        chunk.dirty = False

    def reEncrypt(self, fileId, chunk: ChunkMeta):
        thread = Thread(target=self._reEncrypt, args=(fileId, chunk))
        thread.start()
        self.threads.append(thread)

    def scheduleReEncryption(self, fileId, chunk):
        # if we are not using lazy re-encryption, then re-encrypt instantly
        if self.config['lazy'] == False:
            return self.reEncrypt(fileId, chunk)
        
        # when using lazy loading
        lastAccessTimeDuration = (datetime.now() - chunk.lastAccessTime).total_seconds()
        remainingTime = self.config['lastAccessTimeOffset'] - lastAccessTimeDuration
        # if re-encryption should be executed in less than one second, run it now
        if remainingTime < 1:
            return self.reEncrypt(fileId, chunk)
        
        # else attempt to execute the reEncryption after the remaining time has elapsed
        # TODO: improve this by using cron jobs and a persistence layer to make sure crashes
        # do not result in loss of information about pending re-encryptions
        print(f'[i] re-encryption for chunk {chunk.id} scheduled after {remainingTime} seconds')
        timer = Timer(remainingTime, lambda: self.scheduleReEncryption(fileId, chunk))
        timer.start()

    def terminate(self):
        for thread in self.threads:
            thread.join()
