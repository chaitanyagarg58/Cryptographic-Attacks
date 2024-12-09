from pwn import *
import random
import string

target = process(["python", "./lfsr_server.py"])

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

class LFSR:
    def __init__(self, initial_fill, feedback_map):
        assert len(initial_fill) == len(feedback_map)
        self.initial_fill = initial_fill
        self.fill = initial_fill
        self.feedback_map = feedback_map
    
    def get_next(self):
        next = 0
        for i in range(len(self.fill)):
            next = next ^ (self.fill[i] & self.feedback_map[i])
        return next

    def get_stream(self, length):
        stream = []
        for _ in range(length):
            self.fill.append(self.get_next())
            stream.append(self.fill[0])
            self.fill.pop(0)
            
        return stream
    
    def get_initial_fill(self):
        return ''.join(map(str, self.initial_fill))


def combining_function(x, y, z):
    assert len(x) == len(y)
    assert len(x) == len(z)

    key = []
    for i in range(len(x)):
        key.append((x[i] & y[i]) ^ (y[i] & z[i]) ^ z[i])
    
    key = ''.join(map(str, key))
    return key


feedback_map_x = [1, 1, 0, 0, 0, 0]
feedback_map_y = [1, 0, 0, 1, 0, 0, 0]
feedback_map_z = [1, 0, 1, 0, 0, 0, 0, 0]


## Input string
msg = generate_random_string(100)
msg_length_bits = len(msg.encode().hex()) * 4

recvuntil("Enter the string you want to encrypt: ")
sendline(msg)
recvuntil("Encrypted text (hex):")
cipher = recvline().strip()


## Get Key Stream
key_stream = xor_hex(msg.encode().hex(), cipher)
key_stream_binary = format(int(key_stream, 16), f'0{msg_length_bits}b')


## Guess Initial Fills of X
x_matchs = []
for x_initial in range(2 ** len(feedback_map_x)):
    x_fill = format(x_initial, f'0{len(feedback_map_x)}b')
    x_fill_array = [int(i) for i in x_fill]
    x = LFSR(x_fill_array, feedback_map_x)
    
    x_stream = x.get_stream(msg_length_bits)

    guess = ''.join(map(str, x_stream))

    num_match = 0
    for x_char, stream_char in zip(guess, key_stream_binary):
        if x_char == stream_char:
            num_match += 1
    
    x_matchs.append(num_match)

x_initial = x_matchs.index(max(x_matchs))
x_fill = format(x_initial, f'0{len(feedback_map_x)}b')
x_fill_array = [int(i) for i in x_fill]


## Guess Initial Fills of Z
z_matchs = []
for z_initial in range(2 ** len(feedback_map_z)):
    z_fill = format(z_initial, f'0{len(feedback_map_z)}b')
    z_fill_array = [int(i) for i in z_fill]
    z = LFSR(z_fill_array, feedback_map_z)
    
    z_stream = z.get_stream(msg_length_bits)

    guess = ''.join(map(str, z_stream))

    num_match = 0
    for z_char, stream_char in zip(guess, key_stream_binary):
        if z_char == stream_char:
            num_match += 1
    
    z_matchs.append(num_match)

z_initial = z_matchs.index(max(z_matchs))
z_fill = format(z_initial, f'0{len(feedback_map_z)}b')
z_fill_array = [int(i) for i in z_fill]


## Guess Initial Fills of Y
x = LFSR(x_fill_array, feedback_map_x)
z = LFSR(z_fill_array, feedback_map_z)
x_stream = x.get_stream(msg_length_bits)
z_stream = z.get_stream(msg_length_bits)

y_fill = None

for y_initial in range(2 ** len(feedback_map_y)):
    y_fill = format(y_initial, f'0{len(feedback_map_y)}b')
    y_fill_array = [int(i) for i in y_fill]
    
    y = LFSR(y_fill_array, feedback_map_y)

    y_stream = y.get_stream(msg_length_bits)

    guess = combining_function(x_stream, y_stream, z_stream)

    if guess == key_stream_binary:
        break


recvuntil("Enter Initial Fill x (binary string): ")
sendline(x_fill)
recvuntil("Enter Initial Fill y (binary string): ")
sendline(y_fill)
recvuntil("Enter Initial Fill z (binary string): ")
sendline(z_fill)


output = recvuntil("!\n")
target.close()
