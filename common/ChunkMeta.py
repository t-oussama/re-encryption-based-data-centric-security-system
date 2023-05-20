from datetime import datetime

class ChunkMeta:
    def __init__(self, state = None, encryptionMeta = None, size = None, workerNodeIds = None, chunkId = None) -> None:
        self.state = state
        self.encryptionMeta = encryptionMeta
        self.size = size
        self.workerNodeIds = workerNodeIds
        self.id = chunkId
        self.lastAccessTime = datetime.now()

    def toDict(self):
        return {
            'state': self.state,
            'encryptionMeta': self.encryptionMeta.toDict() if self.encryptionMeta else None,
            'size': self.size,
            'workerNodeIds': self.workerNodeIds,
            'id': self.id,
            'lastAccessTime': self.lastAccessTime.strftime("%m/%d/%Y, %H:%M:%S"),
        }