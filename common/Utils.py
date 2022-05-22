def xor(a: bytes, b: bytes) -> bytes:
    if not len(a) == len(b):
        raise Exception("Expected both xor parameters to have same length")

    result = []
    for i in range(0, len(a)):
        result.append(a[i] ^ b[i])
    return bytes(result)