class User:
    def __init__(self, username: str, pubKey: str, permission: str):
        self.id = username
        self.username = username
        self.pubKey = pubKey
        self.permission = permission
        # list of files the user has access to
        self.files = []