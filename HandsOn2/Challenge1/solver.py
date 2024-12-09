import os

with open('iv.hex', 'r') as file:
    iv = file.readline().strip()

with open('key.hex', 'r') as file:
    key = file.readline().strip()

os.system(f"openssl enc -aes-128-cbc -d -in ciphertext.bin -out plaintext.txt -K {key} -iv {iv}")
os.system(f"cat plaintext.txt")