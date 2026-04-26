from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

# -------------------------- 工具函数 --------------------------
def hex_to_bytes(hex_str):
    """16进制字符串转字节"""
    return binascii.unhexlify(hex_str)

def bytes_to_hex(byte_data):
    """字节转16进制字符串"""
    return binascii.hexlify(byte_data).decode('utf-8')

def xor_bytes(a, b):
    """字节串按位异或（要求a和b长度相同）"""
    return bytes([x ^ y for x, y in zip(a, b)])

def pkcs5_unpad(data):
    """PKCS#5 去填充"""
    pad_len = data[-1]
    # 验证填充合法性（可选，实验中可简化）
    if pad_len < 1 or pad_len > 16:
        raise ValueError("无效的PKCS#5填充")
    return data[:-pad_len]

# -------------------------- CBC 模式实现 --------------------------
def aes_cbc_decrypt(key_hex, ciphertext_hex):
    """
    AES CBC 模式解密（自行实现模式逻辑）
    :param key_hex: 密钥（16进制字符串）
    :param ciphertext_hex: 密文（16进制字符串，前16字节为IV）
    :return: 明文（字符串）
    """
    # 1. 转换为字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    
    # 2. 提取IV（前16字节）和实际密文
    iv = ciphertext[:16]
    ciphertext_blocks = ciphertext[16:]
    
    # 3. 初始化AES ECB解密器（底层仅用ECB）
    aes_ecb = AES.new(key, AES.MODE_ECB)
    
    # 4. 分块解密（每块16字节）
    plaintext_blocks = []
    prev_block = iv  # 第一个分组与IV异或
    block_size = 16
    
    # 遍历所有密文分组
    for i in range(0, len(ciphertext_blocks), block_size):
        curr_cipher_block = ciphertext_blocks[i:i+block_size]
        # ECB解密当前密文分组
        decrypted_block = aes_ecb.decrypt(curr_cipher_block)
        # 与前一个密文分组（或IV）异或得到明文分组
        plaintext_block = xor_bytes(decrypted_block, prev_block)
        plaintext_blocks.append(plaintext_block)
        # 更新前一个密文分组为当前分组
        prev_block = curr_cipher_block
    
    # 5. 拼接明文并去填充
    plaintext = b''.join(plaintext_blocks)
    plaintext_unpad = pkcs5_unpad(plaintext)
    
    # 6. 转换为字符串（假设明文为UTF-8编码）
    return plaintext_unpad.decode('utf-8')

# -------------------------- CTR 模式实现 --------------------------
def aes_ctr_decrypt(key_hex, ciphertext_hex):
    """
    AES CTR 模式解密（自行实现模式逻辑）
    :param key_hex: 密钥（16进制字符串）
    :param ciphertext_hex: 密文（16进制字符串，前16字节为初始计数器）
    :return: 明文（字符串）
    """
    # 1. 转换为字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    
    # 2. 提取初始计数器（前16字节）和实际密文
    nonce = ciphertext[:16]
    ciphertext_data = ciphertext[16:]
    
    # 3. 初始化AES ECB加密器（CTR需要加密计数器生成密钥流）
    aes_ecb = AES.new(key, AES.MODE_ECB)
    
    # 4. 生成密钥流（计数器递增 + ECB加密）
    keystream = b''
    counter = int.from_bytes(nonce, byteorder='big')  # 初始计数器值（大端）
    block_size = 16
    
    # 生成足够长度的密钥流
    while len(keystream) < len(ciphertext_data):
        # 计数器转16字节大端字节串
        counter_bytes = counter.to_bytes(block_size, byteorder='big')
        # ECB加密计数器得到密钥流块
        keystream_block = aes_ecb.encrypt(counter_bytes)
        keystream += keystream_block
        # 计数器+1
        counter += 1
    
    # 5. 密钥流与密文异或得到明文（截断密钥流到密文长度）
    keystream = keystream[:len(ciphertext_data)]
    plaintext = xor_bytes(ciphertext_data, keystream)
    
    # 6. 转换为字符串（UTF-8编码）
    return plaintext.decode('utf-8')

# -------------------------- 测试用例 --------------------------
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