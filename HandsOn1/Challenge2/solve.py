import hashlib
import random


with open('ciphertext.enc', 'rb') as file:
    msg = file.readline()

for i in range(128):
    key = chr(i).encode()
    for _ in range(1, len(msg)):
        key += chr(hashlib.sha256(key).digest()[0]%128).encode()

    flag = b""

    for j in range(len(msg)):
        flag += chr((msg[j] + 128 - key[j])%128).encode()
    
    print(i, flag)