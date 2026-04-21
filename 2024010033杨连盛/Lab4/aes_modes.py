from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
# ===================== 工具函数 =====================
def hex_to_bytes(hex_str):
    """十六进制字符串转字节"""
    return binascii.unhexlify(hex_str)
def bytes_to_hex(byte_data):
    """字节转十六进制字符串"""
    return binascii.hexlify(byte_data).decode()
# ===================== CBC 模式解密 =====================
def aes_cbc_decrypt(key_hex, ciphertext_hex):
    """
    AES CBC 解密
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节为IV）
    :return: 明文字符串
    """
    # 1. 转换为字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    # 2. 拆分 IV（前16字节）和 实际密文
    iv = ciphertext[:16]
    ct = ciphertext[16:]  
    # 3. 初始化 AES-ECB 解密器（CBC 底层使用 ECB）
    cipher = AES.new(key, AES.MODE_ECB) 
    # 4. 逐块解密
    plaintext = b""
    prev_block = iv  # 第一个分组与 IV 异或
    block_size = AES.block_size  # 16字节 
    for i in range(0, len(ct), block_size):
        ct_block = ct[i:i+block_size]
        # AES ECB 解密
        decrypted_block = cipher.decrypt(ct_block)
        # 与前一个密文分组异或得到明文
        pt_block = bytes([a ^ b for a, b in zip(decrypted_block, prev_block)])
        plaintext += pt_block
        # 更新前一个密文分组
        prev_block = ct_block 
    # 5. 去除 PKCS#5 填充
    plaintext = unpad(plaintext, block_size)
    return plaintext.decode()
# ===================== CTR 模式解密 =====================
def aes_ctr_decrypt(key_hex, ciphertext_hex):
    """
    AES CTR 解密
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节为初始计数器）
    :return: 明文字符串
    """
    # 1. 转换为字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex) 
    # 2. 拆分初始计数器（IV）和 实际密文
    nonce = ciphertext[:16]
    ct = ciphertext[16:]  
    # 3. 初始化 AES-ECB 加密器（CTR 始终使用加密）
    cipher = AES.new(key, AES.MODE_ECB)
    # 4. 生成密钥流并异或解密
    plaintext = b""
    counter = int.from_bytes(nonce, byteorder='big')  # 计数器初始值
    block_size = AES.block_size
    for i in range(0, len(ct), block_size):
        # 加密当前计数器生成密钥流
        keystream = cipher.encrypt(counter.to_bytes(block_size, byteorder='big'))
        # 取对应长度的密文块
        ct_block = ct[i:i+block_size]
        # 密钥流与密文异或得到明文
        pt_block = bytes([k ^ c for k, c in zip(keystream, ct_block)])
        plaintext += pt_block
        # 计数器 +1
        counter += 1
    return plaintext.decode()
# ===================== 测试题目 =====================
if __name__ == "__main__":
    print("========== 第 1 题 CBC 解密 ==========")
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print(aes_cbc_decrypt(key1, ct1))
    print("\n========== 第 2 题 CBC 解密 ==========")
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print(aes_cbc_decrypt(key1, ct2))
    print("\n========== 第 3 题 CTR 解密 ==========")
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print(aes_ctr_decrypt(key2, ct3))
    print("\n========== 第 4 题 CTR 解密 ==========")
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print(aes_ctr_decrypt(key2, ct4))