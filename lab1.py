from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad

def main():
    data = 'this is the wireless security lab'
    aes_encrypt(data)
    rc4_encrypt(data)
    # pattern_preservation_data = 'this is good, very good!'
    # ecb_pattern_preservation_check(pattern_preservation_data)

def aes_encrypt(data): 
    # is this key 128 1s?
    bitstring = '1' * 128
    key = int(bitstring, 2).to_bytes(16, byteorder='big')
    initial_data = pad(bytes(data, 'utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(initial_data)
    print('AES Ciphertext: ' + str(ciphertext))
    aes_brute_force(data, ciphertext)
    

def aes_brute_force(data, ciphertext):
    # this function would brute force from 128-bits of 1's to 0 in terms of the key
    # this represents the weakness of the particular key in the lab, but could be reversed
    # to go from 0 to 128-bit 1's if necessary
    bitstring = '1' * 128
    iterator = int(bitstring, 2)
    while iterator > 0:
        key = iterator.to_bytes(16, byteorder='big')
        data3 = pad(bytes(data, 'utf-8'), AES.block_size)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext2 = cipher.encrypt(data3)
        if ciphertext == ciphertext2:
            print('AES Key Found: ' + str(key))
            break
        iterator -= 1        
        

def rc4_encrypt(data): 
    initial_data = data[:]
    bitstring = '1' * 40
    key = int(bitstring, 2).to_bytes(16, 'big')
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(bytes(initial_data, 'utf-8'))
    print('RC4 Ciphertext: ' + str(ciphertext))
    rc4_brute_force(data, ciphertext)
    
def rc4_brute_force(data, ciphertext):
    # this function would brute force from 40-bits of 1's to 0 in terms of the key
    # this represents the weakness of the particular key in the lab, but could be reversed
    # to go from 0 to 40-bit 1's if necessary
    bitstring = '1' * 40
    iterator = int(bitstring, 2)
    while iterator > 0:
        key = iterator.to_bytes(16, byteorder='big')
        cipher = ARC4.new(key)
        ciphertext_check = cipher.encrypt(bytes(data, 'utf-8'))
        if ciphertext == ciphertext_check:
            print('RC4 Key Found: ' + str(key))
            break
        iterator -= 1

def ecb_pattern_preservation_check(data):
    bitstring = '1' * 128
    key = int(bitstring, 2).to_bytes(16, byteorder='big')
    initial_data = pad(bytes(data, 'utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(initial_data)
    print(ciphertext)



if __name__ == "__main__":
    main()