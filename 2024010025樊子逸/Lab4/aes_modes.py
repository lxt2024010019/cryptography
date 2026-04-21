"""
AES CBC 与 CTR 模式加解密实现
要求：自行实现模式逻辑，仅允许使用 AES ECB 底层加密/解密函数。
使用 pycryptodome 库。
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# --------------------- CBC 模式 ---------------------
def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    CBC 模式加密
    1. 随机生成 16 字节 IV
    2. 对明文进行 PKCS#7 填充（此处使用 pad 函数，但也可手写 PKCS#5）
    3. 每个明文块先与前一个密文块（或 IV）异或，再用 AES ECB 加密
    4. 返回 IV + 密文
    """
    iv = os.urandom(16)  # 随机 IV
    cipher = AES.new(key, AES.MODE_ECB)  # 底层 ECB 加密器
    prev = iv
    ciphertext = b''

    # 分块处理
    padded = pad(plaintext, AES.block_size)
    for i in range(0, len(padded), AES.block_size):
        block = padded[i:i+AES.block_size]
        # 异或前一个密文块（或 IV）
        xored = bytes(a ^ b for a, b in zip(block, prev))
        # ECB 加密
        enc_block = cipher.encrypt(xored)
        ciphertext += enc_block
        prev = enc_block

    return iv + ciphertext


def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    CBC 模式解密
    1. 提取前 16 字节为 IV，剩余为实际密文
    2. 对每个密文块用 ECB 解密，再与前一个密文块（或 IV）异或得到明文块
    3. 去除 PKCS#7 填充
    """
    iv = ciphertext[:16]
    actual_cipher = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_ECB)  # 底层 ECB 解密器
    prev = iv
    plaintext = b''

    for i in range(0, len(actual_cipher), AES.block_size):
        block = actual_cipher[i:i+AES.block_size]
        # ECB 解密
        dec_block = cipher.decrypt(block)
        # 异或前一个密文块（或 IV）
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev))
        plaintext += plain_block
        prev = block

    # 去除填充
    return unpad(plaintext, AES.block_size)


# --------------------- CTR 模式 ---------------------
def aes_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    CTR 模式加密（与解密流程完全一致）
    1. 随机生成 16 字节 IV（初始计数器值）
    2. 计数器递增：IV 视为大端整数，依次递增
    3. 每个计数块用 AES ECB 加密生成密钥流，与明文异或
    4. 返回 IV + 密文
    """
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b''

    # 将 IV 转换为整数便于递增
    counter = int.from_bytes(iv, byteorder='big')
    # 处理每一个字节（流密码方式）
    for i in range(0, len(plaintext), AES.block_size):
        # 当前计数器块
        ctr_block = (counter + (i // AES.block_size)).to_bytes(16, byteorder='big')
        # 生成密钥流
        keystream = cipher.encrypt(ctr_block)
        # 取明文对应长度的部分
        block = plaintext[i:i+AES.block_size]
        # 异或
        enc_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        ciphertext += enc_block

    return iv + ciphertext


def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    CTR 模式解密（与加密完全相同）
    """
    iv = ciphertext[:16]
    actual_cipher = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b''

    counter = int.from_bytes(iv, byteorder='big')
    for i in range(0, len(actual_cipher), AES.block_size):
        ctr_block = (counter + (i // AES.block_size)).to_bytes(16, byteorder='big')
        keystream = cipher.encrypt(ctr_block)
        block = actual_cipher[i:i+AES.block_size]
        plain_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        plaintext += plain_block

    return plaintext


# --------------------- 测试与答题 ---------------------
if __name__ == "__main__":
    # 题目提供的密钥与密文（十六进制）
    # 第1题 CBC
    key1 = bytes.fromhex("140b41b22a29beb4061bda66b6747e14")
    cipher1 = bytes.fromhex(
        "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee"
        "2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    )
    plain1 = aes_cbc_decrypt(key1, cipher1).decode('utf-8')
    print("第1题答案:", plain1)

    # 第2题 CBC (同密钥)
    cipher2 = bytes.fromhex(
        "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48"
        "e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    )
    plain2 = aes_cbc_decrypt(key1, cipher2).decode('utf-8')
    print("第2题答案:", plain2)

    # 第3题 CTR
    key3 = bytes.fromhex("36f18357be4dbd77f050515c73fcf9f2")
    cipher3 = bytes.fromhex(
        "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc3"
        "88d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f"
        "5f51eeca32eabedd9afa9329"
    )
    plain3 = aes_ctr_decrypt(key3, cipher3).decode('utf-8')
    print("第3题答案:", plain3)

    # 第4题 CTR (同密钥)
    cipher4 = bytes.fromhex(
        "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa"
        "0e311bde9d4e01726d3184c34451"
    )
    plain4 = aes_ctr_decrypt(key3, cipher4).decode('utf-8')
    print("第4题答案:", plain4)