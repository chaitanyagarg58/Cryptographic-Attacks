from hashlib import md5
from Crypto.Random import get_random_bytes

n = 4
k = 5
iv = b"\x42"*n

def compress(chain: bytes, block: bytes) -> bytes:
    return md5(chain + block).digest()[:n]

def digest(data) -> bytes:
    chain_value = iv
    for idx in range(0, len(data), n):
        block = data[idx:idx+n]
        chain_value = compress(chain_value, block)
    return chain_value

h_origin = b"aaaa"
h_origin_hash = compress(iv, h_origin)

h_matrix = [[]]
h_map = {}
hset = set()
for i in range(2**k):
    rand_block = get_random_bytes(n)
    while rand_block in hset:
        rand_block = get_random_bytes(n)
    hset.add(rand_block)
    h_matrix[0].append([compress(h_origin_hash, rand_block), rand_block])

    h_map[h_matrix[0][i][0]] = [0, i]


for p in range(k - 1, -1, -1):
    h_matrix.append([])
    for i in range(2 ** p):
        idx = 2 * i
        hmap = {}
        for _ in range(2 ** (4 * n)):
            m1 = get_random_bytes(n)
            c1_ = compress(h_matrix[k - 1 - p][idx][0], m1)
            while c1_ in hmap:
                m1 = get_random_bytes(n)
                c1_ = compress(h_matrix[k - 1 - p][idx][0], m1)
            
            hmap[c1_] = m1
        
        m2 = get_random_bytes(n)
        c2_ = compress(h_matrix[k - 1 - p][idx + 1][0], m2)
        while c2_ not in hmap:
            m2 = get_random_bytes(n)
            c2_ = compress(h_matrix[k - 1 - p][idx + 1][0], m2)
        

        h_matrix[k - p].append([c2_, hmap[c2_], m2])
        if h_matrix[k - p][i][0] != compress(h_matrix[k - 1 - p][2 * i][0], h_matrix[k - p][i][1]):
            raise Exception("Fault 1")
        elif h_matrix[k - p][i][0] != compress(h_matrix[k - 1 - p][2 * i + 1][0], h_matrix[k - p][i][2]):
            raise Exception("Fault 2")
        
        h_map[c2_] = [k - p, i]


with open ("save.txt", "w") as file:
    file.write(f"{n} {k} {iv.decode()}\n")

    for i in range(2**k):
        file.write(f"{h_matrix[0][i][0].hex()} {h_matrix[0][i][1].hex()}\n")
    
    for level in range(1, k + 1):
        for i in range(2 ** (k - level)):
            file.write(f"{h_matrix[level][i][0].hex()} {h_matrix[level][i][1].hex()} {h_matrix[level][i][2].hex()}\n")

    file.write(f"{len(h_map)}\n")

    for key in h_map:
        file.write(f"{key.hex()} {h_map[key][0]} {h_map[key][1]}\n")
