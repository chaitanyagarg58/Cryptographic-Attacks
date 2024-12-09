# Q1

openssl x509 -in GlobalSign_Root_CA.pem -text -noout | grep "Public Key Algorithm" | awk '{print $NF}'
## Answer = rsaEncryption

# Q2

openssl x509 -in GlobalSign_Root_CA.pem -text -noout | grep -m 1 "Signature Algorithm" | awk '{print $NF}'
## Answer = sha1WithRSAEncryption

# Q3

openssl x509 -in Amazon_Root_CA_1.pem -text -noout | grep -m 1 "Signature Algorithm" | awk '{print $NF}'
## Answer = sha256WithRSAEncryption

# Q4

openssl x509 -in Certigna.pem -text -noout | grep "Not After"
## Answer = 29-06-2027


### Flag = cs406{c3rt1f13d_1n_c3rt1f1c4t10n}