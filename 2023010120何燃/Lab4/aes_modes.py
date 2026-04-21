from Crypto.Cipher import AES

def xor_bytes(b1, b2):
    """
    XOR 两个字节串，常用于底层数据块的异或操作
    """
    return bytes(x ^ y for x, y in zip(b1, b2))

def pkcs5_unpad(data):
    """
    去除 PKCS#5 填充
    检查最后一个字节的值，即为填充的长度，然后截断
    """
    padding_len = data[-1]
    return data[:-padding_len]

def decrypt_cbc(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """
    自行实现的 CBC 模式解密逻辑
    """
    # 1. 前 16 字节为 IV
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    
    # 仅使用 ECB 模式作为基础分组加密引擎
    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b""
    prev_block = iv
    
    # 2. 按 16 字节分组进行处理
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        # 解密当前密文分组
        decrypted_block = cipher.decrypt(block)
        # 3. 与前一个密文分组（或初始 IV）异或得到明文
        plaintext_block = xor_bytes(decrypted_block, prev_block)
        plaintext += plaintext_block
        prev_block = block
        
    # 4. 去除 PKCS#5 填充
    return pkcs5_unpad(plaintext)

def decrypt_ctr(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """
    自行实现的 CTR 模式解密逻辑
    """
    # 1. 前 16 字节为初始计数器值 (IV)
    initial_counter = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]
    
    cipher = AES.new(key, AES.MODE_ECB)
    
    plaintext = b""
    # 将 16 字节的 IV 转换为大端序整数作为计数器
    counter_int = int.from_bytes(initial_counter, byteorder='big')
    
    # 2. 遍历密文，生成密钥流并异或
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        
        # 将计数器转回 16 字节，并使用 ECB 加密生成密钥流
        counter_bytes = counter_int.to_bytes(16, byteorder='big')
        keystream_block = cipher.encrypt(counter_bytes)
        
        # 3. 将密钥流与密文逐字节异或（注意最后一个分组可能不足 16 字节）
        plaintext_block = xor_bytes(block, keystream_block[:len(block)])
        plaintext += plaintext_block
        
        # 4. 计数器递增
        counter_int += 1
        
    # CTR 模式不需要填充，直接返回
    return plaintext

if __name__ == "__main__":
    # --- 实验题目测试数据 ---
    
    # CBC 测试数据
    key_cbc = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    ct1_cbc = bytes.fromhex("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    ct2_cbc = bytes.fromhex("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")

    # CTR 测试数据
    key_ctr = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    ct1_ctr = bytes.fromhex("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    ct2_ctr = bytes.fromhex("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")

    # 输出解密结果，将其直接填入 Lab4.md
    print("=== Lab4 解密结果 ===")
    print(f"第 1 题答案: {decrypt_cbc(key_cbc, ct1_cbc).decode('utf-8')}")
    print(f"第 2 题答案: {decrypt_cbc(key_cbc, ct2_cbc).decode('utf-8')}")
    print(f"第 3 题答案: {decrypt_ctr(key_ctr, ct1_ctr).decode('utf-8')}")
    print(f"第 4 题答案: {decrypt_ctr(key_ctr, ct2_ctr).decode('utf-8')}")