HEADER = "_Have you heard about the quick brown fox which jumps over the lazy dog?\n__The decimal number system uses the digits 0123456789!\n___The flag is: "

with open("ciphertext.bin", 'rb') as file:
    cipher = file.read().hex()
    cipher = [cipher[i:i+32] for i in range(0, len(cipher), 32)]

mapping = {}
for cip, char in zip(cipher, HEADER):
    mapping[cip] = char

FLAG = ""

for cip in cipher[len(HEADER):]:
    if cip in mapping.keys():
        FLAG += mapping[cip]
    else:
        FLAG += "~"

print(FLAG)