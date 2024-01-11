from Crypto.Cipher import AES
from Crypto.Cipher import ARC4

data = 'this is the wireless security lab'
key = bytes('1111111111111111', 'utf-8')
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(bytes(data, 'utf-8'))