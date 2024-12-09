import ecdsa
import hashlib
import random
import string

import ecdsa.ellipticcurve

FLAG = "REDACTED"

VARIANT1_PRIVKEY = random.randrange(1, ecdsa.NIST256p.generator.order())
VARIANT2_PRIVKEY = random.randrange(1, ecdsa.NIST256p.generator.order())

def point_to_tuple(point):
    return (int(point.x()), int(point.y()))

def tuple_to_point(tup):
    return ecdsa.ellipticcurve.Point(ecdsa.ellipticcurve.CurveFp(ecdsa.NIST256p.curve.p(), ecdsa.NIST256p.curve.a(), ecdsa.NIST256p.curve.b()), tup[0], tup[1])

G = ecdsa.NIST256p.generator # Should be using a differnt curve for actual EdDSA; NIST256p used here for simplicity

VARIANT1_PUBKEY = VARIANT1_PRIVKEY * G
VARIANT2_PUBKEY = VARIANT2_PRIVKEY * G


def eddsa_variant1_sign(msg):
    q = G.order()
    r = int(hashlib.sha256(msg + str(VARIANT1_PUBKEY.x()).encode()).hexdigest(), base=16) % q
    R = r * G
    h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
    s = (r + h * VARIANT1_PRIVKEY) % q
    return R, s

def eddsa_variant1_verify(msg, R, s):
    q = G.order()
    h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT1_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
    P1 = s * G
    P2 = R + h * VARIANT1_PUBKEY
    return P1 == P2


def eddsa_variant2_sign(msg):
    q = G.order()
    r = int(hashlib.sha256(msg[:len(msg)//2] + str(VARIANT2_PRIVKEY).encode()).hexdigest(), base=16) % q
    R = r * G
    h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
    s = (r + h * VARIANT2_PRIVKEY) % q
    return R, s

def eddsa_variant2_verify(msg, R, s):
    q = G.order()
    h = int(hashlib.sha256(str(R.x()).encode() + str(VARIANT2_PUBKEY.x()).encode() + msg).hexdigest(), base=16) % q
    P1 = s * G
    P2 = R + h * VARIANT2_PUBKEY
    return P1 == P2



if __name__ == '__main__':
    NUM_SIGNS = 5

    print("-----VARIANT 1-----")
    print(f"Public Key: {point_to_tuple(VARIANT1_PUBKEY)}\n")

    for i in range(NUM_SIGNS):
        msg = input(f"Enter message you want to get signature of [{i+1}/{NUM_SIGNS}]: ").encode()
        R, s = eddsa_variant1_sign(msg)
        print(f"Signature: {(point_to_tuple(R), int(s))}\n")

    rand_msg = ''.join(random.choices(string.printable[:62], k=100))
    print(f"Sign this message using EdDSA Variant 1: {rand_msg}")
    R_1, s_1 = eval(input("Enter signature (point_to_tuple(R), int(s)): "))
    R_1 = tuple_to_point(R_1)
    print(type(R_1), s_1)

    if eddsa_variant1_verify(rand_msg.encode(), R_1, s_1):
        print("Signature is valid!\n")
    else:
        print("Invalid Signature!")
        exit(0)


    print("-----VARIANT 2-----")
    print(f"Public Key: {point_to_tuple(VARIANT2_PUBKEY)}\n")

    for i in range(NUM_SIGNS):
        msg = input(f"Enter message you want to get signature of [{i+1}/{NUM_SIGNS}]: ").encode()
        R, s = eddsa_variant2_sign(msg)
        print(f"Signature: {(point_to_tuple(R), int(s))}\n")

    rand_msg = ''.join(random.choices(string.printable[:62], k=100))
    print(f"Sign this message using EdDSA Variant 2: {rand_msg}")
    R_2, s_2 = eval(input("Enter signature (point_to_tuple(R), int(s)): "))
    R_2 = tuple_to_point(R_2)

    if eddsa_variant2_verify(rand_msg.encode(), R_2, s_2):
        print("Signature is valid!\n")
    else:
        print("Invalid Signature!")
        exit(0)
    
    print("Congratulations! You have passed the trials!")
    print(f"The flag is: {FLAG}")
