import random

def xor_hex(hex1, hex2):
    return hex(int(hex1, 16) ^ int(hex2, 16))[2:]

num_repeat = 120
S = []
IV1 = None
IV2 = None
V = None

PRIV_KEY = random.randrange(1, 2 ** (253 * 8))
K = [IV1, IV2, V]
for i in range(253):
    K.append((PRIV_KEY >> 8 * (252 - i)) % 256)


def reinitialize():
    global S, K
    S = []
    for i in range(256):
        S.append(i)
    K[0] = IV1
    K[1] = IV2
    K[2] = V

    j = 0
    for i in range(256):
        j = (j + S[i] + K[i]) % 256
        S[i], S[j] = S[j], S[i]


def generate_keystream(input_length_bytes):
    global S
    i = 0
    j = 0
    
    keystream = ''
    for _ in range(input_length_bytes):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        keystream += hex(S[t])[2:].zfill(2)
    
    return keystream

if __name__ == "__main__":
    IV_Used = []
    print(f"Num of Trial: {num_repeat}")
    while True:
        choice = int(input("Enter Choice (1. Encrypt Messages, 2. Guess Key): "))
        if choice not in [1, 2]:
            print("Invalid Choice")
            exit(1)
        
        if choice == 2:
            break

        IV1 = int(input("Enter First Byte of IV (int): "))
        if IV1 < 0 or IV1 > 255:
            print("Invalid Input")
            exit(1)
        IV2 = int(input("Enter Second Byte of IV (int): "))
        if IV2 < 0 or IV2 > 255:
            print("Invalid Input")
            exit(1)

        if (IV1, IV2) in IV_Used:
            print("Repeating Same IV choice is not allowed.")
            exit(1)
        
        IV_Used.append((IV1, IV2))
        K[0] = IV1
        K[1] = IV2
        V_Used = []
        for i in range(num_repeat):
            
            V = random.randrange(0, 256)
            while V in V_Used:
                V = random.randrange(0, 256)
            V_Used.append(V)
            print("Final Byte of IV (int):", V)

            K[2] = V

            reinitialize()

            user_input = input(f"[{i+1}/{num_repeat}] Enter Message: ")

            input_hex = user_input.encode().hex()

            input_length_bytes = len(input_hex) // 2

            key_hex = generate_keystream(input_length_bytes)

            encrypted_hex = xor_hex(input_hex, key_hex)

            print("Encrypted text (hex):", encrypted_hex)


    guess = input("Enter key prefix (hex): ")
    for i in range(0, len(guess), 2):
        if int(guess[i:i+2], 16) != K[3  + i // 2]:
            print (f"Num of correct bytes in prefix: {i // 2}/{len(guess) // 2}")
            exit(0)

    print (f"Num of correct bytes in prefix: {len(guess) // 2}/{len(guess) // 2}")