from pwn import *
import time
from hashlib import sha256

HOST = "0.cloud.chals.io"
PORT = 19258

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
target = process(["python3", "./server.py"])
# target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp, end='')
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp, end='')
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp, end='')
    return resp


recvuntil("Length: ")
flag_len = int(recvuntil("\n")[:-1])

flag = []
for idx in range(0, flag_len, 4):
    recvuntil(f"{flag_len - 1}: ")
    sendline(str(idx))
    recvuntil("Value: ")
    val = int(recvuntil("\n")[:-1])
    recvuntil("Proof: ")
    proof = eval(recvuntil("]\n")[:-1])
    flag.append(chr(val))

    nxt = proof[-1]
    for f in range(256):
        hash = sha256(chr(f).encode()).digest().hex()
        
        if hash == nxt:
            flag.append(chr(f))
            break

    nxt = proof[-2]
    for f1 in range(256):
        done = False
        for f2 in range(256):
            hash1 = sha256(chr(f1).encode()).digest()
            hash2 = sha256(chr(f2).encode()).digest()
            hash = sha256(hash1 + hash2).digest().hex()

            if hash == nxt:
                flag.append(chr(f1))
                flag.append(chr(f2))
                done = True
                break

        if done:
            break   

print("\n\nFlag : ", ''.join(flag), "\n")

target.close()
