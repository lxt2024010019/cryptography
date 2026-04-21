from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def aes_ecb_decrypt(key, ciphertext):
    """使用AES ECB模式解密"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def cbc_decrypt(key, ciphertext_hex):
    """CBC模式解密"""
    # 将十六进制字符串转换为字节
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 提取IV（前16字节）和实际密文
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # 将密文分割成16字节的块
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    
    # 解密每个块
    decrypted_blocks = []
    prev_block = iv
    for block in blocks:
        # 使用AES ECB模式解密当前块
        decrypted_block = aes_ecb_decrypt(key, block)
        # 与前一个密文块（或IV）异或
        plaintext_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])
        decrypted_blocks.append(plaintext_block)
        prev_block = block
    
    # 合并所有明文块
    plaintext = b''.join(decrypted_blocks)
    
    # 去除PKCS#5填充
    plaintext = unpad(plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')

def ctr_decrypt(key, ciphertext_hex):
    """CTR模式解密"""
    # 将十六进制字符串转换为字节
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 提取初始计数器值（前16字节）
    nonce = ciphertext[:16]
    ciphertext = ciphertext[16:]
    
    # 生成密钥流
    keystream = b''
    counter = int.from_bytes(nonce, byteorder='big')
    block_size = AES.block_size
    
    # 为每个密文块生成密钥流
    for i in range(0, len(ciphertext), block_size):
        # 递增计数器
        counter_bytes = counter.to_bytes(block_size, byteorder='big')
        # 使用AES ECB模式加密计数器值
        cipher = AES.new(key, AES.MODE_ECB)
        keystream_block = cipher.encrypt(counter_bytes)
        keystream += keystream_block
        counter += 1
    
    # 截断密钥流以匹配密文长度
    keystream = keystream[:len(ciphertext)]
    
    # 与密文逐字节异或
    plaintext = bytes([a ^ b for a, b in zip(ciphertext, keystream)])
    
    return plaintext.decode('utf-8')

# 第1题：CBC模式解密
key1 = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14")
ciphertext1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
plaintext1 = cbc_decrypt(key1, ciphertext1)
print("第1题解密结果:", plaintext1)

# 第2题：CBC模式解密
ciphertext2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
plaintext2 = cbc_decrypt(key1, ciphertext2)
print("第2题解密结果:", plaintext2)

# 第3题：CTR模式解密
key2 = binascii.unhexlify("36f18357be4dbd77f050515c73fcf9f2")
ciphertext3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
plaintext3 = ctr_decrypt(key2, ciphertext3)
print("第3题解密结果:", plaintext3)

# 第4题：CTR模式解密
ciphertext4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
plaintext4 = ctr_decrypt(key2, ciphertext4)
print("第4题解密结果:", plaintext4)
