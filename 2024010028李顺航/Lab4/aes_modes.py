from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii

# ====================== 工具函数 ======================
def pkcs5_unpad(data):
    """PKCS#5 去填充：最后一个字节的值就是填充的长度"""
    pad_len = data[-1]
    return data[:-pad_len]

def hex_to_bytes(hex_str):
    """十六进制字符串转字节流"""
    return binascii.unhexlify(hex_str)

# ====================== CBC 模式解密 ======================
def aes_cbc_decrypt(key_hex, ciphertext_hex):
    # 1. 十六进制转字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    
    # 2. 拆分 IV（前16字节）和 密文
    iv = ciphertext[:16]
    cipher_blocks = [ciphertext[16+i:16+i+16] for i in range(0, len(ciphertext)-16, 16)]
    
    # 3. 初始化 AES-ECB 解密器
    aes = AES.new(key, AES.MODE_ECB)
    plaintext = b''
    prev_cipher = iv  # 第一个分组用 IV 异或
    
    # 4. 逐分组解密
    for block in cipher_blocks:
        decrypted_block = aes.decrypt(block)  # ECB 解密
        plain_block = strxor(decrypted_block, prev_cipher)  # 异或
        plaintext += plain_block
        prev_cipher = block  # 更新前一个密文分组
    
    # 5. 去除 PKCS#5 填充
    plaintext = pkcs5_unpad(plaintext)
    return plaintext.decode('utf-8')

# ====================== CTR 模式解密 ======================
def aes_ctr_decrypt(key_hex, ciphertext_hex):
    # 1. 十六进制转字节
    key = hex_to_bytes(key_hex)
    ciphertext = hex_to_bytes(ciphertext_hex)
    
    # 2. 拆分初始计数器 IV（前16字节）和 密文
    iv = ciphertext[:16]
    cipher_data = ciphertext[16:]
    
    # 3. 初始化 AES-ECB 加密器
    aes = AES.new(key, AES.MODE_ECB)
    keystream = b''
    counter = int.from_bytes(iv, byteorder='big')  # 初始计数器
    
    # 4. 生成密钥流（加密递增的计数器）
    for i in range(len(cipher_data)):
        if i % 16 == 0:
            # 每16字节更新计数器并加密生成新的密钥流块
            counter_block = counter.to_bytes(16, byteorder='big')
            keystream += aes.encrypt(counter_block)
            counter += 1
    
    # 5. 密钥流与密文异或得到明文
    plaintext = strxor(cipher_data, keystream[:len(cipher_data)])
    return plaintext.decode('utf-8')

# ====================== 解题 ======================
if __name__ == '__main__':
    print("===== 第1题：CBC 模式解密 =====")
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print(aes_cbc_decrypt(key1, ct1))
    
    print("\n===== 第2题：CBC 模式解密 =====")
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print(aes_cbc_decrypt(key1, ct2))
    
    print("\n===== 第3题：CTR 模式解密 =====")
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304ec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print(aes_ctr_decrypt(key2, ct3))
    
    print("\n===== 第4题：CTR 模式解密 =====")
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print(aes_ctr_decrypt(key2, ct4))