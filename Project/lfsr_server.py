import random

class LFSR:
    def __init__(self, initial_fill, feedback_map):
        assert len(initial_fill) == len(feedback_map)
        self.initial_fill = initial_fill.copy()
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


def xor_hex(hex1, hex2):
    return hex(int(hex1, 16) ^ int(hex2, 16))[2:]


feedback_map_x = [1, 1, 0, 0, 0, 0]
feedback_map_y = [1, 0, 0, 1, 0, 0, 0]
feedback_map_z = [1, 0, 1, 0, 0, 0, 0, 0]

x = LFSR([random.getrandbits(1) for _ in range(len(feedback_map_x))], feedback_map_x)
y = LFSR([random.getrandbits(1) for _ in range(len(feedback_map_y))], feedback_map_y)
z = LFSR([random.getrandbits(1) for _ in range(len(feedback_map_z))], feedback_map_z)

def get_key(length):
    stream_x = x.get_stream(length)
    stream_y = y.get_stream(length)
    stream_z = z.get_stream(length)

    key_binary = combining_function(stream_x, stream_y, stream_z)
    key_hex = hex(int(key_binary, 2))[2:]

    return key_hex

if __name__ == "__main__":
    user_input = input("Enter the string you want to encrypt: ")
    
    input_hex = user_input.encode().hex()

    input_length_bits = len(input_hex) * 4

    key_hex = get_key(input_length_bits)

    encrypted_hex = xor_hex(input_hex, key_hex)

    print("Encrypted text (hex):", encrypted_hex)

    fill_x = input("Enter Initial Fill x (binary string): ")
    fill_y = input("Enter Initial Fill y (binary string): ")
    fill_z = input("Enter Initial Fill z (binary string): ")
    
    if fill_x != x.get_initial_fill():
        print("Attack Failure!")
    elif fill_y != y.get_initial_fill():
        print("Attack Failure!")
    elif fill_z != z.get_initial_fill():
        print("Attack Failure!")
    else:
        print("Attack Success!")

