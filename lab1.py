from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Util.Padding import pad, unpad

def main():
    data = 'this is the wireless security lab'
    aes_encrypt(data)
    rc4_encrypt(data)
    pattern_preservation_data1 = 'good good good good bad'
    pattern_preservation_data2 = 'good good good good'
    error_propagation_data = 'i hope this does not propagate!'
    ecb_pattern_preservation_check(pattern_preservation_data1, pattern_preservation_data2)
    ecb_error_propagation_check(error_propagation_data)
    cbc_pattern_preservation_check(pattern_preservation_data1, pattern_preservation_data2)
    cbc_error_propagation_check(error_propagation_data)

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
        padded_data = pad(bytes(data, 'utf-8'), AES.block_size)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext_check = cipher.encrypt(padded_data)
        if ciphertext == ciphertext_check:
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

def ecb_pattern_preservation_check(data1, data2):
    bitstring1 = '1' * 128
    key1 = int(bitstring1, 2).to_bytes(16, byteorder='big')
    initial_data1 = pad(bytes(data1, 'utf-8'), AES.block_size)
    cipher1 = AES.new(key1, AES.MODE_ECB)
    ciphertext1 = cipher1.encrypt(initial_data1)
    print('ECB Pattern Preservation P Ciphertext 1: ' + str(ciphertext1))
    bitstring2 = '1' * 128
    key2 = int(bitstring2, 2).to_bytes(16, byteorder='big')
    initial_data2 = pad(bytes(data2, 'utf-8'), AES.block_size)
    cipher2 = AES.new(key2, AES.MODE_ECB)
    ciphertext2 = cipher2.encrypt(initial_data2)
    print('ECB Pattern Preservation Ciphertext 2: ' + str(ciphertext2))

def ecb_error_propagation_check(data):
    bitstring = '1' * 128
    key = int(bitstring, 2).to_bytes(16, byteorder='big')
    initial_data = pad(bytearray(data, 'utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(initial_data)
    print('ECB Error Propagation Ciphertext Before Change: ' + str(ciphertext))
    ciphertext = bytearray(ciphertext)
    ciphertext[8] = 10
    ciphertext = bytes(ciphertext)
    print('ECB Error Propagation Ciphertext After Change: ' + str(ciphertext))
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print('ECB Error Propagation Plaintext After Change: ' + str(decrypted_data))

def cbc_pattern_preservation_check(data1, data2):
    bitstring1 = '1' * 128
    key1 = int(bitstring1, 2).to_bytes(16, byteorder='big')
    initial_data1 = pad(bytes(data1, 'utf-8'), AES.block_size)
    cipher1 = AES.new(key1, AES.MODE_CBC)
    ciphertext1 = cipher1.encrypt(initial_data1)
    print('ECB Pattern Preservation P Ciphertext 1: ' + str(ciphertext1))
    bitstring2 = '1' * 128
    key2 = int(bitstring2, 2).to_bytes(16, byteorder='big')
    initial_data2 = pad(bytes(data2, 'utf-8'), AES.block_size)
    cipher2 = AES.new(key2, AES.MODE_CBC)
    ciphertext2 = cipher2.encrypt(initial_data2)
    print('ECB Pattern Preservation Ciphertext 2: ' + str(ciphertext2))

def cbc_error_propagation_check(data):
    bitstring = '1' * 128
    key = int(bitstring, 2).to_bytes(16, byteorder='big')
    initial_data = pad(bytearray(data, 'utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(initial_data)
    print('ECB Error Propagation Ciphertext Before Change: ' + str(ciphertext))
    ciphertext = bytearray(ciphertext)
    ciphertext[8] = 10
    ciphertext = bytes(ciphertext)
    print('ECB Error Propagation Ciphertext After Change: ' + str(ciphertext))
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    print('ECB Error Propagation Plaintext After Change: ' + str(decrypted_data))

    



if __name__ == "__main__":
    main()