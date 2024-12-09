from pwn import *
import hashlib
import ecdsa
import random
from Crypto.Util.number import inverse

HOST = "0.cloud.chals.io"
PORT = 31888

# Uncomment the 'process' line below when you want to test locally, uncomment the 'remote' line below when you want to execute your exploit on the server
target = process(["python", "./server.py"])
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


def point_to_tuple(point):
    return (int(point.x()), int(point.y()))

def tuple_to_point(tup):
    return ecdsa.ellipticcurve.Point(ecdsa.ellipticcurve.CurveFp(ecdsa.NIST256p.curve.p(), ecdsa.NIST256p.curve.a(), ecdsa.NIST256p.curve.b()), tup[0], tup[1])


# -----VARIANT 1-----
recvuntil("Public Key: ")
VARIANT1_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'

msgs = ["a"] * 5
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 1: ")
challenge_msg_1 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT1_PUBKEY: the public key point used in VARIANT 1 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 1 signatures for each of the messages you had submitted earlier
#    - challenge_msg_1: the message whose VARIANT 1 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature

G = ecdsa.NIST256p.generator

msg = msgs[0].encode()
R = sigs[0][0]
s = sigs[0][1]
q = G.order()

r = int(hashlib.sha256(msg + str(VARIANT1_PUBKEY.x()).encode()).hexdigest(), base=16) % q
h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q

VARIANT1_PRIVKEY = ((s - r) * inverse(h, q)) % q

msg = challenge_msg_1

r = int(hashlib.sha256(msg + str(VARIANT1_PUBKEY.x()).encode()).hexdigest(), base=16) % q
R = r * G
h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
s = (r + h * VARIANT1_PRIVKEY) % q
# ===== YOUR CODE ABOVE =====

recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")

# -----VARIANT 2-----
recvuntil("Public Key: ")
VARIANT2_PUBKEY = tuple_to_point(eval(recvline().strip()))

# ===== YOUR CODE BELOW =====
# Variables You Have:
#     - VARIANT2_PUBKEY: the public key point used in VARIANT 1 signatures
# Enter the five message (str) you want to get signed in the list 'msgs'

msgs = ["ab", "ac", "a", "a", "a"]
# ===== YOUR CODE ABOVE =====

assert len(msgs) == 5
sigs = []
for msg in msgs:
    recvuntil("]: ")
    sendline(msg)
    recvuntil("Signature: ")
    sigs.append(eval(recvline().strip()))
    sigs[-1] = (tuple_to_point(sigs[-1][0]), sigs[-1][1])

recvuntil("Variant 2: ")
challenge_msg_2 = recvline().strip().encode()

# ===== YOUR CODE BELOW =====
# Variables You Have:
#    - VARIANT2_PUBKEY: the public key point used in VARIANT 2 signatures
#    - msgs: the list of messages (str) you had submitted earlier
#    - sigs: list of respective (R, s) VARIANT 2 signatures for each of the messages you had submitted earlier
#    - challenge_msg_2: the message whose VARIANT 2 signature you have to provide
# Set the variable 'R' to the point R of the signature
# Set the variable 's' to the value s of the signature

G = ecdsa.NIST256p.generator

msg1 = msgs[0].encode()
R1 = sigs[0][0]
s1 = sigs[0][1]

msg2 = msgs[1].encode()
R2 = sigs[1][0]
s2 = sigs[1][1]

q = G.order()

h1 = int(hashlib.sha256(str(R1.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg1).hexdigest(), base=16) % q
h2 = int(hashlib.sha256(str(R2.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg2).hexdigest(), base=16) % q

VARIANT2_PRIVKEY = ((s1 - s2) * inverse(h1 - h2, q)) % q

msg = challenge_msg_2

r = int(hashlib.sha256(msg[:len(msg)//2] + str(VARIANT2_PRIVKEY).encode()).hexdigest(), base=16) % q
R = r * G
h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
s = (r + h * VARIANT2_PRIVKEY) % q
# ===== YOUR CODE ABOVE =====

recvuntil(")): ")
sendline(f"({point_to_tuple(R)}, {int(s)})")

recvall()
target.close()


