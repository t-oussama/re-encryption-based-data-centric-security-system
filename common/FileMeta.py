class FileMeta:
    def __init__(self, name, path, chunks, permissions) -> None:
        self.name = name
        self.path = path
        self.chunks = chunks
        self.permissions = permissions

    def toDict(self):
        chunksDicts = {}
        for chunkId in self.chunks.keys():
            chunksDicts[chunkId] = self.chunks[chunkId].toDict()

        return {
            'name': self.name,
            'path': self.path,
            'chunks': chunksDicts,
            'permissions': self.permissions,
        }