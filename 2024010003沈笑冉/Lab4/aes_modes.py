from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

# 工具函数
def hex2bytes(hex_str):
    return binascii.unhexlify(hex_str.strip())

def bytes2utf8(data):
    return data.decode('utf-8')

# CBC 模式解密（手动实现）
def aes_cbc_decrypt(key_hex, ciphertext_hex):
    key = hex2bytes(key_hex)
    ct = hex2bytes(ciphertext_hex)
    
    iv = ct[:16]
    ciphertext = ct[16:]
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    plaintext = b''
    prev_block = iv
    
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i+block_size]
        decrypted_block = cipher.decrypt(block)
        plain_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
        plaintext += plain_block
        prev_block = block
    
    plaintext = unpad(plaintext, block_size)
    return bytes2utf8(plaintext)

# CTR 模式解密（手动实现）
def aes_ctr_decrypt(key_hex, ciphertext_hex):
    key = hex2bytes(key_hex)
    ct = hex2bytes(ciphertext_hex)
    
    nonce = ct[:16]
    ciphertext = ct[16:]
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = AES.block_size
    plaintext = b''
    counter = int.from_bytes(nonce, byteorder='big')
    
    for i in range(0, len(ciphertext), block_size):
        keystream_block = cipher.encrypt(counter.to_bytes(block_size, byteorder='big'))
        ct_block = ciphertext[i:i+block_size]
        plain_block = bytes(x ^ y for x, y in zip(ct_block, keystream_block))
        plaintext += plain_block
        counter += 1
    
    return bytes2utf8(plaintext)

# 主程序：直接输出答案
if __name__ == '__main__':
    print("="*50)
    
    # 第1题 CBC
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题答案：", aes_cbc_decrypt(key1, ct1))
    
    # 第2题 CBC
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题答案：", aes_cbc_decrypt(key1, ct2))
    
    # 第3题 CTR
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题答案：", aes_ctr_decrypt(key2, ct3))
    
    # 第4题 CTR
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题答案：", aes_ctr_decrypt(key2, ct4))
    
    print("="*50)