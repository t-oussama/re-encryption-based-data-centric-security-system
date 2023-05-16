import random
import string
import time

filePath = f'../data/random_text_{time.time()}'
print(f'[+] Generating file in: {filePath}')
with open(filePath, 'w') as f:
    randomString = ''.join(random.choices(string.ascii_lowercase, k=1024*1024*1024))
    f.write(randomString)
print('[+] DONE')