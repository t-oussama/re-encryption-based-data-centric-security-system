from datetime import datetime
from threading import Timer
from .WorkerNode import WorkerNode
from common.encryption_engine.EncryptionEngine import L

class Scheduler:
    def __init__(self, config, encryptionEngine, workerNodes):
        self.config = config
        self.encryptionEngine = encryptionEngine
        self.workerNodes = workerNodes

    def _reEncrypt(self, fileId, chunk):
        newSecret = self.encryptionEngine.genEncryptionMeta().secret
        rk = self.encryptionEngine.getReEncryptionKey(chunk.encryptionMeta.secret, newSecret, chunk.size+L)
        workerNode = self.workerNodes[chunk.workerNodeIds[0]]
        WorkerNode.reEncrypt(workerNode['host'], workerNode['port'], fileId, chunk.id, rk, chunk.encryptionMeta.iv)
        chunk.encryptionMeta.secret = newSecret

    def scheduleReEncryption(self, fileId, chunk):
        # if we are not using lazy re-encryption, then re-encrypt instantly
        if self.config['lazy'] == False:
            return self._reEncrypt(fileId, chunk)
        
        # when using lazy loading
        lastAccessTimeDuration = (datetime.now() - chunk.lastAccessTime).total_seconds()
        remainingTime = self.config['lastAccessTimeOffset'] - lastAccessTimeDuration
        # if re-encryption should be executed in less than one second, run it now
        if remainingTime < 1:
            return self._reEncrypt(fileId, chunk)
        
        # else attempt to execute the reEncryption after the remaining time has elapsed
        # TODO: improve this by using cron jobs and a persistence layer to make sure crashes
        # do not result in loss of information about pending re-encryptions
        print(f'[i] re-encryption for chunk {chunk.id} scheduled after {remainingTime} seconds')
        timer = Timer(remainingTime, lambda: self.scheduleReEncryption(fileId, chunk))
        timer.start()