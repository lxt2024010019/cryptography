from Crypto.Cipher import AES
import binascii

def pkcs5_unpad(data: bytes) -> bytes:
    """移除PKCS#5填充：最后一个字节的值等于填充的长度"""
    pad_length = data[-1]
    return data[:-pad_length]

def aes_cbc_decrypt(ciphertext_hex: str, key_hex: str) -> str:
    """
    自行实现AES-CBC模式解密
    步骤：提取IV → 分块ECB解密 → 与前一个密文块异或 → 移除填充
    """
    # 十六进制转字节串
    ciphertext = binascii.unhexlify(ciphertext_hex)
    key = binascii.unhexlify(key_hex)
    
    # 提取前16字节作为IV，剩余为实际密文
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    # 按16字节分块
    block_size = 16
    cipher_blocks = [actual_ciphertext[i:i+block_size] 
                     for i in range(0, len(actual_ciphertext), block_size)]
    
    # 初始化AES-ECB模式（仅用基础加密功能，符合实验要求）
    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b''
    prev_block = iv  # 第一个块与IV异或
    
    for block in cipher_blocks:
        # 1. ECB解密当前密文块
        decrypted_block = cipher.decrypt(block)
        # 2. 与前一个密文块异或得到明文块
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += plain_block
        # 3. 更新前一个块为当前密文块
        prev_block = block
    
    # 移除PKCS#5填充并转UTF-8字符串
    plaintext = pkcs5_unpad(plaintext)
    return plaintext.decode('utf-8')

def aes_ctr_decrypt(ciphertext_hex: str, key_hex: str) -> str:
    """
    自行实现AES-CTR模式解密
    步骤：提取初始计数器 → 生成递增计数器 → 加密计数器得到密钥流 → 与密文异或
    """
    ciphertext = binascii.unhexlify(ciphertext_hex)
    key = binascii.unhexlify(key_hex)
    
    # 提取前16字节作为初始计数器（nonce）
    nonce = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    block_size = 16
    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b''
    # 将初始计数器转为大端序整数，方便递增
    counter = int.from_bytes(nonce, byteorder='big')
    
    for i in range(0, len(actual_ciphertext), block_size):
        # 1. 生成当前计数器的16字节大端序表示
        counter_bytes = counter.to_bytes(16, byteorder='big')
        # 2. 加密计数器得到密钥流块
        keystream_block = cipher.encrypt(counter_bytes)
        # 3. 取当前密文块
        cipher_block = actual_ciphertext[i:i+block_size]
        # 4. 密文与密钥流异或得到明文块
        plain_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
        plaintext += plain_block
        # 5. 计数器加1
        counter += 1
    
    return plaintext.decode('utf-8')

# 测试题目（运行后直接输出答案）
if __name__ == "__main__":
    # 第1、2题共用密钥
    cbc_key = "140b41b22a29beb4061bda66b6747e14"
    # 第3、4题共用密钥
    ctr_key = "36f18357be4dbd77f050515c73fcf9f2"
    
    # 题目1
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题答案：", aes_cbc_decrypt(cipher1, cbc_key))
    
    # 题目2
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题答案：", aes_cbc_decrypt(cipher2, cbc_key))
    
    # 题目3
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题答案：", aes_ctr_decrypt(cipher3, ctr_key))
    
    # 题目4
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题答案：", aes_ctr_decrypt(cipher4, ctr_key))