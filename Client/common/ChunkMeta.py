class ChunkMeta:
    def __init__(self, state = None, encryptionMeta = None, size = None, workerNodeIds = None) -> None:
        self.state = state
        self.encryptionMeta = encryptionMeta
        self.size = size
        self.workerNodeIds = workerNodeIds

    def toDict(self):
        return {
            'state': self.state,
            'encryptionMeta': self.encryptionMeta.toDict() if self.encryptionMeta else None,
            'size': self.size,
            'workerNodeIds': self.workerNodeIds,
        }