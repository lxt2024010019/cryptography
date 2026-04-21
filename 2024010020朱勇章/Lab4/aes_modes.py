from Crypto.Cipher import AES
import binascii

# ===================== 核心工具函数 =====================
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """字节级异或操作（两个字节串长度必须相同）"""
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs5_unpad(data: bytes) -> bytes:
    """移除 PKCS#5 填充（CBC 模式解密后使用）"""
    pad_len = data[-1]
    # 验证填充合法性（可选，确保填充值等于填充长度）
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("无效的 PKCS#5 填充")
    return data[:-pad_len]

# ===================== CBC 模式解密 =====================
def aes_cbc_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    AES CBC 模式解密（128位密钥）
    :param key_hex: 16进制编码的密钥（32字符 = 16字节）
    :param ciphertext_hex: 16进制编码的密文（前16字节是IV，后为实际密文）
    :return: 解密后的明文（字符串）
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 2. 拆分 IV（前16字节）和实际密文
    iv = ciphertext[:AES.block_size]
    ciphertext_blocks = ciphertext[AES.block_size:]
    
    # 3. 初始化 AES ECB 解密器（CBC 底层用 ECB 解密每个分组）
    aes_ecb = AES.new(key, AES.MODE_ECB)
    
    # 4. 分块解密（CBC 核心逻辑）
    plaintext_blocks = []
    prev_block = iv  # 初始为 IV，后续为前一个密文分组
    block_size = AES.block_size
    
    # 遍历所有密文分组（每次取16字节）
    for i in range(0, len(ciphertext_blocks), block_size):
        curr_block = ciphertext_blocks[i:i+block_size]
        # ECB 解密当前密文分组
        decrypted_block = aes_ecb.decrypt(curr_block)
        # 与前一个分组异或得到明文分组
        plain_block = xor_bytes(decrypted_block, prev_block)
        plaintext_blocks.append(plain_block)
        # 更新前一个分组为当前密文分组
        prev_block = curr_block
    
    # 5. 拼接明文并移除 PKCS#5 填充
    plaintext = b''.join(plaintext_blocks)
    plaintext_unpadded = pkcs5_unpad(plaintext)
    
    # 6. 字节转字符串（UTF-8 编码）
    return plaintext_unpadded.decode('utf-8')

# ===================== CTR 模式解密 =====================
def aes_ctr_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    AES CTR 模式解密（128位密钥）
    :param key_hex: 16进制编码的密钥（32字符 = 16字节）
    :param ciphertext_hex: 16进制编码的密文（前16字节是初始计数器，后为实际密文）
    :return: 解密后的明文（字符串）
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 2. 拆分初始计数器（IV）和实际密文
    counter_init = ciphertext[:AES.block_size]
    ciphertext_data = ciphertext[AES.block_size:]
    
    # 3. 初始化 AES ECB 加密器（CTR 用 ECB 加密计数器生成密钥流）
    aes_ecb = AES.new(key, AES.MODE_ECB)
    
    # 4. 生成密钥流（CTR 核心逻辑）
    keystream = b''
    counter = int.from_bytes(counter_init, byteorder='big')  # 初始计数器转整数
    block_size = AES.block_size
    
    # 生成足够长度的密钥流（覆盖密文长度）
    while len(keystream) < len(ciphertext_data):
        # 计数器转 16 字节大端序
        counter_bytes = counter.to_bytes(block_size, byteorder='big')
        # 加密计数器生成密钥块
        keystream_block = aes_ecb.encrypt(counter_bytes)
        keystream += keystream_block
        # 计数器递增
        counter += 1
    
    # 5. 密钥流与密文异或得到明文（截断密钥流到密文长度）
    plaintext = xor_bytes(ciphertext_data, keystream[:len(ciphertext_data)])
    
    # 6. 字节转字符串（UTF-8 编码）
    return plaintext.decode('utf-8')

# ===================== 题目解密测试 =====================
if __name__ == "__main__":
    # 第1题：CBC解密
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题答案：", aes_cbc_decrypt(key1, cipher1))
    
    # 第2题：CBC解密
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题答案：", aes_cbc_decrypt(key1, cipher2))
    
    # 第3题：CTR解密
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题答案：", aes_ctr_decrypt(key3, cipher3))
    
    # 第4题：CTR解密
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题答案：", aes_ctr_decrypt(key3, cipher4))