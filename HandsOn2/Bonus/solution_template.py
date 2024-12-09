from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 15176

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
target = process(["python3", "./server.py"])
# target = remote(HOST, PORT)

def recvuntil(msg):
    resp = target.recvuntil(msg.encode()).decode()
    print(resp)
    return resp

def sendline(msg):
    print(msg)
    target.sendline(msg.encode())

def recvline():
    resp = target.recvline().decode()
    print(resp)
    return resp

def recvall():
    resp = target.recvall().decode()
    print(resp)
    return resp


recvuntil("IV: ")
IV = bytes.fromhex(recvline())

recvuntil("Flag: ")
flag_enc = bytes.fromhex(recvline())


def validate_padding(iv_hex: str, ciphertext_hex: str) -> bool:
    recvuntil("validated:\n")
    sendline(ciphertext_hex)
    recvuntil("IV:\n")
    sendline(iv_hex)
    response = recvline()
    valid_padding = ("Valid Padding!" in response)
    return valid_padding


# ===== YOUR CODE BELOW =====
# The variable IV has the iv (as a bytes object)
# The variable flag_enc has the ciphertext (as a bytes object)
# You can call the function validate_padding(iv_hex: str, ciphertext_hex: str) -> bool which takes in the hex of the iv (str) and hex of the ciphertext (str) and returns True if the corresponding plaintext has valid padding, and return False otherwise (as dictated by the server's response)
iv_hex = IV.hex()
iv_hex = [iv_hex[i:i+2] for i in range(0, len(iv_hex), 2)]

C = [flag_enc[i:i+16].hex() for i in range(0, len(flag_enc), 16)]
C = [[block[i:i+2] for i in range(0, len(block), 2)] for block in C]
P = [["00"] * 16 for _ in range(len(C))]

for k in range(len(P)):
    C_dash = ["00"] * 16
    for byte in range(15, -1, -1):
        for i in range(256):
            C_dash[byte] = str(hex(i)[2:]).zfill(2)
            attack_str = ''.join(C_dash) + ''.join(C[k])

            if validate_padding(IV.hex(), attack_str):
                P2_dash_byte = bytes.fromhex(str(hex(16 - byte)[2:]).zfill(2))
                C_dash_byte = bytes.fromhex(C_dash[byte])
                if k != 0:
                    C_k_minus_1_byte = bytes.fromhex(C[k - 1][byte])
                else:
                    C_k_minus_1_byte = bytes.fromhex(iv_hex[byte])
                P[k][byte] = strxor(P2_dash_byte, strxor(C_dash_byte, C_k_minus_1_byte)).hex()
                
                P2_dash_byte_2 = bytes.fromhex(str(hex(17 - byte)[2:]).zfill(2))
                for b in range(byte, 16):
                    if k != 0:
                        C_k_minus_1_b = bytes.fromhex(C[k - 1][b])
                    else:
                        C_k_minus_1_b = bytes.fromhex(iv_hex[b])
                    C_dash[b] = strxor(P2_dash_byte_2, strxor(bytes.fromhex(P[k][b]), C_k_minus_1_b)).hex()
                break

P = [''.join(block) for block in P]
FLAG = bytes.fromhex(''.join(P)).decode('ascii')
print(FLAG)

# ===== YOUR CODE BELOW =====

target.close()
