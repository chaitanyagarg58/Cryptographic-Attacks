from pwn import *
from hashlib import md5
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from tqdm import tqdm

HOST = "0.cloud.chals.io"
PORT = 33976

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python3", "./server.py"])
target = remote(HOST, PORT)

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



# ===== YOUR CODE BELOW =====
# Set your target hash (in hex) in the variable "target_hash"

def compress(chain: bytes, block: bytes) -> bytes:
    return md5(chain + block).digest()[:n]

def digest(data) -> bytes:
    chain_value = iv
    for idx in range(0, len(data), n):
        block = data[idx:idx+n]
        chain_value = compress(chain_value, block)
    return chain_value

with open("save.txt", "r") as file:
    line = file.readline()

    l0 = line.split()
    n = int(l0[0])
    k = int(l0[1])
    iv = l0[2].encode()

    h_matrix = [[]]

    for i in range(2**k):
        line = file.readline()
        l0 = line.split()

        h_matrix[0].append([bytes.fromhex(l0[0]), bytes.fromhex(l0[1])])
    
    for level in range(1, k + 1):
        h_matrix.append([])
        for i in range(2 ** (k - level)):
            line = file.readline()
            l0 = line.split()

            h_matrix[-1].append([bytes.fromhex(l0[0]), bytes.fromhex(l0[1]), bytes.fromhex(l0[2])])
    
    num = int(file.readline())
    h_map = {}

    for _ in range(num):
        line = file.readline()
        l0 = line.split()

        h_map[bytes.fromhex(l0[0])] = [int(l0[1]), int(l0[2])]

padding_block = pad(b'', n)

target_hash = compress(h_matrix[k][0][0], padding_block).hex()
# ===== YOUR CODE ABOVE =====

recvuntil("Give me your target hash (in hex): ")
sendline(target_hash)

# ===== YOUR CODE BELOW =====
# Implement the function "get_cpft_message(prefix: bytes) -> bytes" to return a messgae which starts with the given prefix and has the same hash as the target hash

def get_cpft_message(prefix: bytes) -> bytes:
    level = None
    index = None
    
    prefix = pad(prefix, n)
    message = prefix

    while True:
        dgst = digest(message)

        if dgst in h_map:
            level = h_map[dgst][0]
            index = h_map[dgst][1]
            break
        
        new_block = get_random_bytes(n)
        message = prefix + new_block
    
    while level < k:
        nextIdx = index // 2
        if index % 2 == 0:
            message = message + h_matrix[level + 1][nextIdx][1]
        else:
            message = message + h_matrix[level + 1][nextIdx][2]
        level += 1
        index = nextIdx

    return message

# ===== YOUR CODE ABOVE =====

NUM_TRIALS = 100
for _ in range(NUM_TRIALS):
    recvuntil("Custom Prefix: ")
    custom_prefix = bytes.fromhex(recvline())
    recvuntil("Enter your message: ")
    message = get_cpft_message(custom_prefix)
    sendline(message.hex())

recvline()
recvline()

target.close()
