from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad
# import nltk 
# nltk.download('words')
# from nltk.corpus import words

def main():
    # used for implementation of 
    # word_list = words.words()
    data = 'this is the wireless security lab'
    aes_encrypt(data)
    rc4_encrypt(data)

def aes_encrypt(data): 
    # is this key 128 1s?
    key = bytes('1111111111111111', 'utf-8')
    data = pad(bytes(data, 'utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    print(ciphertext)

def rc4_encrypt(data): 
    # is this a 40 bit key?
    key = bytes('11111', 'utf-8')
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(bytes(data, 'utf-8'))
    print(ciphertext)




if __name__ == "__main__":
    main()