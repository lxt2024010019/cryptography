from Crypto.Cipher import AES
import binascii

def pkcs7_unpad(data: bytes) -> bytes:
    """PKCS#7填充去除，符合CBC模式要求"""
    pad_len = data[-1]
    return data[:-pad_len]

def aes_cbc_decrypt(key_hex: str, cipher_hex: str) -> str:
    """
    自行实现AES-CBC解密逻辑，仅用AES核心运算
    :param key_hex: 十六进制密钥
    :param cipher_hex: 十六进制密文（前16字节为IV）
    :return: 明文字符串
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    cipher_data = binascii.unhexlify(cipher_hex)

    # 2. 拆分IV和密文
    iv = cipher_data[:16]
    ciphertext = cipher_data[16:]

    # 3. 初始化AES ECB模式（仅用核心运算，不使用内置CBC）
    cipher = AES.new(key, AES.MODE_ECB)

    # 4. 手动实现CBC解密逻辑
    plaintext = b""
    prev_block = iv
    block_size = 16

    for i in range(0, len(ciphertext), block_size):
        cipher_block = ciphertext[i:i+block_size]
        # ECB解密当前块
        decrypted_block = cipher.decrypt(cipher_block)
        # 与前一个块（IV）异或得到明文
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext += plain_block
        # 更新前块为当前密文块
        prev_block = cipher_block

    # 5. 去除PKCS#7填充
    return pkcs7_unpad(plaintext).decode("utf-8")

def aes_ctr_decrypt(key_hex: str, cipher_hex: str) -> str:
    """
    自行实现AES-CTR解密逻辑，仅用AES核心运算
    :param key_hex: 十六进制密钥
    :param cipher_hex: 十六进制密文（前16字节为初始计数器）
    :return: 明文字符串
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    cipher_data = binascii.unhexlify(cipher_hex)

    # 2. 拆分初始计数器和密文
    nonce = cipher_data[:16]
    ciphertext = cipher_data[16:]

    # 3. 初始化AES ECB模式
    cipher = AES.new(key, AES.MODE_ECB)

    # 4. 手动实现CTR解密逻辑
    plaintext = b""
    block_size = 16
    counter = int.from_bytes(nonce, byteorder="big")

    for i in range(0, len(ciphertext), block_size):
        # 生成当前计数器字节
        counter_bytes = counter.to_bytes(block_size, byteorder="big")
        # 加密计数器生成密钥流
        keystream_block = cipher.encrypt(counter_bytes)
        # 取当前密文块
        cipher_block = ciphertext[i:i+block_size]
        # 异或得到明文
        plain_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
        plaintext += plain_block
        # 计数器+1
        counter += 1

    # CTR无填充，直接返回
    return plaintext.decode("utf-8")

if __name__ == "__main__":
    # ========== CBC 题目 ==========
    key_cbc = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    print("第1题（CBC解密）：", aes_cbc_decrypt(key_cbc, cipher1))
    print("第2题（CBC解密）：", aes_cbc_decrypt(key_cbc, cipher2))

    # ========== CTR 题目 ==========
    key_ctr = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    print("第3题（CTR解密）：", aes_ctr_decrypt(key_ctr, cipher3))
    print("第4题（CTR解密）：", aes_ctr_decrypt(key_ctr, cipher4))