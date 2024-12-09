from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST = "0.cloud.chals.io"
PORT = 33517

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
# target = process(["python3", "./server.py"])
target = remote(HOST, PORT)

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


def choice1(params: str) -> str:
    recvuntil("parameters: ")
    sendline("1")
    recvuntil("parameters: ")
    sendline(params)
    recvuntil("hex): ")
    ciphertext_hex = recvline().strip()
    return ciphertext_hex

def choice2(params_enc: str) -> (bool, str):
    recvuntil("parameters: ")
    sendline("2")
    recvuntil("hex): ")
    sendline(params_enc)
    resp = recvline().strip()
    if resp == "Invalid parameters! Incorrect padding or Non-ASCII characters detected!":
        recvuntil("hex): ")
        return False, recvline().strip()
    elif resp == "Your parameters have been successfully submitted!":
        return False, ""
    elif resp == "Welcome, admin!":
        recvuntil("flag: ")
        return True, recvline().strip()
        


# ===== YOUR CODE BELOW =====
# Use the function choice1(params) the send your parameters (str) to the server (Choice 1)
# It returns (given that your input was successfully processed) the ciphertext as a hex-string
# Use the function choice2(params_enc) to send your encrypted parameters (hex string) to the server (Choice 2)
# It returns a 2-tuple: the first component being a boolean indicating whether you got admin access (True) or not (False), the second compoennt being the hex-string returned by the server (empty string in the case that the server returns nothing)
    
x1 = "a"*15 + "="
x2 = "random"

y1_y2 = choice1(x1 + x2)
y1 = y1_y2[:32]

y_dash = "ff"*16
_, z1_z2 = choice2(y_dash + y1)

z2 = z1_z2[32:]

key = strxor(x1.encode(), strxor(bytes.fromhex(y_dash), bytes.fromhex(z2)))

cipher = AES.new(key, AES.MODE_CBC, iv=key)
ciphertext = cipher.encrypt(pad("admin=true".encode(), AES.block_size))

_, encrypted_flag = choice2(ciphertext.hex())

cipher = AES.new(key, AES.MODE_CBC, iv=key)
flag_padded = cipher.decrypt(bytes.fromhex(encrypted_flag))
flag = unpad(flag_padded, AES.block_size).decode()

print(flag)

# ===== YOUR CODE ABOVE =====

try:
    target.close()
except:
    pass
