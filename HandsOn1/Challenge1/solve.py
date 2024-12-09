from Crypto.Util.strxor import strxor

with open('ciphertext1.enc', 'rb') as f1:
    cip1 = f1.readline()


with open('ciphertext2.enc', 'rb') as f2:
    cip2 = f2.readline()

cip = strxor(cip1, cip2)

flag = b'cs406{one_time_pad_key_reuse_compromises_security!!!}'
msg =  b'Cryptanalysis frequently involves statistical attacks'

print(strxor(cip, msg))
print(strxor(cip, flag))