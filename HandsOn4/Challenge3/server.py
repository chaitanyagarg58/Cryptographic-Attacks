import ecdsa
import hashlib
import random

FLAG = "REDACTED"

if __name__ == "__main__":
    G = ecdsa.SECP256k1.generator
    order = G.order()

    priv_key = random.randrange(1,order)
    pub_key = ecdsa.ecdsa.Public_key(G, G*priv_key)
    x1 = ecdsa.ecdsa.Private_key(pub_key, priv_key)

    k = random.randrange(1, 2**127)

    msg1 = "To infinity and beyond!"
    msg2 = "Live long, and prosper."

    h1 = int(hashlib.sha256(msg1.encode()).hexdigest(), base=16)
    h2 = int(hashlib.sha256(msg2.encode()).hexdigest(), base=16)
    
    sign1 = x1.sign(h1, k)
    sign2 = x1.sign(h2, k)

    r1, s1 = sign1.r, sign1.s
    r2, s2 = sign2.r, sign2.s

    print("Message 1:", msg1)
    print(f"Signature:\nr = {r1}\ns = {s1}")
    print()
    print("Message 2:", msg2)
    print(f"Signature:\nr = {r2}\ns = {s2}")
    print()

    nonce_rec = int(input("Enter recovered nonce (as decimal): "))
    privkey_rec = int(input("Enter recvoered private_key (as decimal): "))
    print()

    if(nonce_rec == k and privkey_rec == priv_key):
        print("Correct! Here's the flag: ", FLAG)
    else:
        print("Incorrect Parameters!")
