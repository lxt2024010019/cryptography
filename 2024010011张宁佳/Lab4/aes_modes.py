from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ------------------- 工具函数 -------------------
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """逐字节异或，要求长度相同"""
    return bytes(x ^ y for x, y in zip(a, b))

def aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    """使用 AES ECB 解密单个 16 字节分组"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """使用 AES ECB 加密单个 16 字节分组（用于 CTR 生成密钥流）"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

# ------------------- CBC 解密（自行实现） -------------------
def cbc_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    AES-CBC 解密
    - key_hex: 十六进制密钥字符串
    - ciphertext_hex: 十六进制密文字符串（前16字节为IV）
    - 返回：解密后的明文字符串（自动去除 PKCS#7 填充）
    """
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(ciphertext_hex)

    iv = data[:16]
    ciphertext = data[16:]

    assert len(ciphertext) % 16 == 0, "密文长度必须是16的倍数"

    plaintext_blocks = []
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_ecb_decrypt(key, block)
        plain_block = xor_bytes(decrypted, prev)
        plaintext_blocks.append(plain_block)
        prev = block

    plaintext = b''.join(plaintext_blocks)

    # 去除 PKCS#7 填充
    try:
        plaintext = unpad(plaintext, AES.block_size)
    except ValueError:
        # 如果填充不正确，返回原始字节（仅供调试）
        pass
    return plaintext.decode('utf-8')

# ------------------- CTR 解密（自行实现） -------------------
def ctr_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    AES-CTR 解密（加密与解密相同）
    - key_hex: 十六进制密钥字符串
    - ciphertext_hex: 十六进制密文字符串（前16字节为初始计数器 nonce/IV）
    - 返回：解密后的明文字符串
    """
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(ciphertext_hex)

    nonce = data[:16]          # 初始计数器值
    ciphertext = data[16:]

    # 将计数器解释为大端整数（标准做法）
    counter = int.from_bytes(nonce, byteorder='big')
    plaintext = bytearray()

    for i in range(0, len(ciphertext), 16):
        # 当前计数器值
        current_counter = (counter + (i // 16)).to_bytes(16, byteorder='big')
        keystream = aes_ecb_encrypt(key, current_counter)
        chunk = ciphertext[i:i+16]
        # 逐字节异或，处理最后可能不满 16 字节的分组
        for j in range(len(chunk)):
            plaintext.append(chunk[j] ^ keystream[j])

    return bytes(plaintext).decode('utf-8')

# ------------------- 题目测试 -------------------
if __name__ == "__main__":
    # 第1题
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题明文:", cbc_decrypt(key1, cipher1))

    # 第2题（密钥同第1题）
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题明文:", cbc_decrypt(key1, cipher2))

    # 第3题
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题明文:", ctr_decrypt(key3, cipher3))

    # 第4题（密钥同第3题）
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题明文:", ctr_decrypt(key3, cipher4))