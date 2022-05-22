class User:
    def __init__(self, username: str, pubKey: str, permission: str):
        self.username = username
        self.pubKey = pubKey
        self.permission = permission