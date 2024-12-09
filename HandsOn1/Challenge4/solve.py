def base_to_base(num: list, base_from: int, base_to: int):
    def decimal_to_base(num: int, base: int):
        ans = []
        while num > 0:
            ans.append(num % base)
            num = num // base
        ans.reverse()
        return ans

    def base_to_decimal(num: list, base: int):
        ans = 0
        for i in num:
            ans = ans * base + i
        return ans

    tmp = base_to_decimal(num, base_from)
    return decimal_to_base(tmp, base_to)

with open('ciphertext.enc', 'rb') as file:
    cip = file.read()

with open('keyfile', 'rb') as file:
    key = list(file.read(len(cip)))

c_list = base_to_base(cip, 256, 255)
p_list = []

for ci, ki in zip(c_list, key):
    pi = (ci - ki + 1 + 255) % 255
    p_list.append(pi)

m_list = base_to_base(p_list, 255, 256)

result_string = ''.join([chr(hex_value) for hex_value in m_list])
print(result_string)