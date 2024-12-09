a=$(openssl mac -digest sha256 -macopt hexkey:"$(cat key.hex)" -in message.txt HMAC)
b=$(openssl mac -cipher AES-128-CBC -macopt hexkey:"$(cat key.hex)" -in message.txt CMAC)
c=$(openssl mac -cipher AES-128-GCM -macopt hexkey:"$(cat key.hex)" -macopt hexiv:"$(cat iv.hex)" -in message.txt GMAC)
echo CS406{$a\_$b\_$c}