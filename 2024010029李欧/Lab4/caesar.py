from Crypto.Cipher import AES
import binascii


def cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    实现AES-CBC模式解密
    :param key: AES密钥
    :param ciphertext: 包含IV的完整密文（IV在前16字节）
    :return: 解密后的明文（已去除PKCS#5填充）
    """
    # 提取初始向量IV（前16字节）
    iv = ciphertext[:16]
    # 剩余部分为实际密文
    ciphertext = ciphertext[16:]
    # 初始化AES-ECB模式（CBC底层依赖ECB）
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    prev_cipher = iv  # 前一个密文分组，初始为IV

    for i in range(0, len(ciphertext), 16):
        # 取出当前密文分组（16字节）
        block = ciphertext[i:i+16]
        # 用ECB模式解密当前分组
        decrypted_block = cipher.decrypt(block)
        # 与前一个密文分组（或IV）异或得到明文分组
        plaintext_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_cipher)])
        plaintext += plaintext_block
        # 更新前一个密文分组
        prev_cipher = block

    # 去除PKCS#5填充（填充字节值等于填充长度）
    padding_len = plaintext[-1]
    plaintext = plaintext[:-padding_len]
    return plaintext


def ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    实现AES-CTR模式解密
    :param key: AES密钥
    :param ciphertext: 包含初始计数器的完整密文（初始计数器在前16字节）
    :return: 解密后的明文（无填充）
    """
    # 提取初始计数器值（前16字节）
    counter_bytes = ciphertext[:16]
    # 剩余部分为实际密文
    ciphertext = ciphertext[16:]
    # 初始化AES-ECB模式（CTR底层依赖ECB）
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    # 将初始计数器转为大整数，方便递增
    counter = int.from_bytes(counter_bytes, byteorder='big')

    for i in range(0, len(ciphertext), 16):
        # 生成当前计数器值的16字节大端表示
        current_counter_bytes = counter.to_bytes(16, byteorder='big')
        # 加密计数器值生成密钥流块
        keystream = cipher.encrypt(current_counter_bytes)
        # 取出当前密文块
        block = ciphertext[i:i+16]
        # 与密钥流异或得到明文块
        plaintext_block = bytes([a ^ b for a, b in zip(block, keystream)])
        plaintext += plaintext_block
        # 计数器+1（CTR核心逻辑：计数器递增）
        counter += 1

    return plaintext


if __name__ == "__main__":
    # 题目1：CBC模式解密
    key1 = binascii.unhexlify("140b41b22a29beb4061bda66b6747e14")
    ciphertext1 = binascii.unhexlify(
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    )
    plaintext1 = cbc_decrypt(key1, ciphertext1)
    print(f"第1题明文: {plaintext1.decode('utf-8')}")

    # 题目2：CBC模式解密
    ciphertext2 = binascii.unhexlify(
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    )
    plaintext2 = cbc_decrypt(key1, ciphertext2)
    print(f"第2题明文: {plaintext2.decode('utf-8')}")

    # 题目3：CTR模式解密
    key3 = binascii.unhexlify("36f18357be4dbd77f050515c73fcf9f2")
    ciphertext3 = binascii.unhexlify(
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    )
    plaintext3 = ctr_decrypt(key3, ciphertext3)
    print(f"第3题明文: {plaintext3.decode('utf-8')}")

    # 题目4：CTR模式解密
    ciphertext4 = binascii.unhexlify(
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    )
    plaintext4 = ctr_decrypt(key3, ciphertext4)
    print(f"第4题明文: {plaintext4.decode('utf-8')}")