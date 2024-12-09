from pwn import *
import random
import string

target = process(["python", "./wep_rc4_server.py"])

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


def xor_hex(hex1, hex2):
    return hex(int(hex1, 16) ^ int(hex2, 16))[2:]

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string


recvuntil("Num of Trial: ")
num_repeat = int(recvline().strip())


## Guess K3
recvuntil("Enter Choice (1. Encrypt Messages, 2. Guess Key): ")
sendline("1")
IV1 = 3
IV2 = 255
recvuntil("Enter First Byte of IV (int): ")
sendline(str(IV1))
recvuntil("Enter Second Byte of IV (int): ")
sendline(str(IV2))

K3_guess_map = {}
for i in range(num_repeat):
    recvuntil("Final Byte of IV (int): ")
    V = int(recvline().strip())

    msg = generate_random_string(100)

    recvuntil("Enter Message: ")
    sendline(msg)

    recvuntil("Encrypted text (hex): ")
    cipher_hex = recvline().strip()

    keystream_hex = xor_hex(cipher_hex, msg.encode().hex())

    keystream_firstbyte = keystream_hex[:2]

    guess = (int(keystream_firstbyte, 16) - V - 6) % 256

    K3_guess_map[guess] = K3_guess_map.get(guess, 0) + 1

K3 = max(K3_guess_map, key=K3_guess_map.get)


## Guess K4
recvuntil("Enter Choice (1. Encrypt Messages, 2. Guess Key): ")
sendline("1")
IV1 = 4
IV2 = 255
recvuntil("Enter First Byte of IV (int): ")
sendline(str(IV1))
recvuntil("Enter Second Byte of IV (int): ")
sendline(str(IV2))

K4_guess_map = {}
for i in range(num_repeat):
    recvuntil("Final Byte of IV (int): ")
    V = int(recvline().strip())

    msg = generate_random_string(100)

    recvuntil("Enter Message: ")
    sendline(msg)

    recvuntil("Encrypted text (hex): ")
    cipher_hex = recvline().strip()

    keystream_hex = xor_hex(cipher_hex, msg.encode().hex())

    keystream_firstbyte = keystream_hex[:2]

    guess = (int(keystream_firstbyte, 16) - V - K3 - 10) % 256

    K4_guess_map[guess] = K4_guess_map.get(guess, 0) + 1

K4 = max(K4_guess_map, key=K4_guess_map.get)




## Guess K5
recvuntil("Enter Choice (1. Encrypt Messages, 2. Guess Key): ")
sendline("1")
IV1 = 5
IV2 = 255
recvuntil("Enter First Byte of IV (int): ")
sendline(str(IV1))
recvuntil("Enter Second Byte of IV (int): ")
sendline(str(IV2))

K5_guess_map = {}
for i in range(num_repeat):
    recvuntil("Final Byte of IV (int): ")
    V = int(recvline().strip())

    msg = generate_random_string(100)

    recvuntil("Enter Message: ")
    sendline(msg)

    recvuntil("Encrypted text (hex): ")
    cipher_hex = recvline().strip()

    keystream_hex = xor_hex(cipher_hex, msg.encode().hex())

    keystream_firstbyte = keystream_hex[:2]

    guess = (int(keystream_firstbyte, 16) - V - K3 - K4 - 15) % 256

    K5_guess_map[guess] = K5_guess_map.get(guess, 0) + 1

K5 = max(K5_guess_map, key=K5_guess_map.get)



## Final Key Prediction
recvuntil("Enter Choice (1. Encrypt Messages, 2. Guess Key): ")
sendline("2")

recvuntil("Enter key prefix (hex): ")
key_prefix = hex(K3)[2:].zfill(2) + hex(K4)[2:].zfill(2) + hex(K5)[2:].zfill(2)
sendline(key_prefix)

recvuntil("\n")
target.close()