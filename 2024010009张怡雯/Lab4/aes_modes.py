from Crypto.Cipher import AES

def aes_cbc_decrypt(key_hex: str, ciphertext_hex: str) -> str:
   
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    iv = ciphertext[:16]
    ct_blocks = ciphertext[16:]

    # 仅使用 ECB 模式作为单块解密原语
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    plaintext_blocks = []

    # 逐块处理密文
    for i in range(0, len(ct_blocks), 16):
        block = ct_blocks[i:i+16]
        decrypted = cipher_ecb.decrypt(block)          # AES-ECB 解密
        plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))  # 与前一块异或
        plaintext_blocks.append(plain_block)
        prev_block = block  # 更新前一个密文块用于下一轮

    plaintext_padded = b''.join(plaintext_blocks)

    # PKCS#7 填充去除
    pad_len = plaintext_padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    if plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    
    return plaintext_padded[:-pad_len].decode('utf-8')


def aes_ctr_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    init_counter = ciphertext[:16]
    ct_bytes = ciphertext[16:]

    # 计数器按大端序解析为整数
    counter_int = int.from_bytes(init_counter, byteorder='big')
    cipher_ecb = AES.new(key, AES.MODE_ECB)

    plaintext_bytes = bytearray()
    # 按 16 字节分块处理（最后一块可能不足 16 字节）
    for i in range(0, len(ct_bytes), 16):
        counter_bytes = counter_int.to_bytes(16, byteorder='big')
        keystream = cipher_ecb.encrypt(counter_bytes)  # 加密计数器生成密钥流

        chunk = ct_bytes[i:i+16]
        plain_chunk = bytes(a ^ b for a, b in zip(keystream, chunk))  # 异或解密
        plaintext_bytes.extend(plain_chunk)

        counter_int += 1  # 计数器递增

    return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    # 第 1 题: CBC 模式
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("Q1 (CBC):", aes_cbc_decrypt(key1, cipher1))

    # 第 2 题: CBC 模式
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("Q2 (CBC):", aes_cbc_decrypt(key1, cipher2))

    # 第 3 题: CTR 模式
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("Q3 (CTR):", aes_ctr_decrypt(key3, cipher3))

    # 第 4 题: CTR 模式
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("Q4 (CTR):", aes_ctr_decrypt(key3, cipher4))
