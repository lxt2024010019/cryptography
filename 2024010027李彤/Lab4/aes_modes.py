from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def aes_cbc_decrypt(key_hex, ciphertext_hex):
    """
    AES CBC 模式解密
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节是IV）
    :return: 明文字符串
    """
    # 1. 转字节
    key = binascii.unhexlify(key_hex)
    ct = binascii.unhexlify(ciphertext_hex)
    
    # 2. 拆分 IV（前16字节）和 密文
    iv = ct[:16]
    ciphertext = ct[16:]
    
    # 3. AES CBC 解密
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    
    # 4. 去除 PKCS#5 填充
    plaintext = unpad(plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')

def aes_ctr_decrypt(key_hex, ciphertext_hex):
    """
    AES CTR 模式解密
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节是初始计数器）
    :return: 明文字符串
    """
    key = binascii.unhexlify(key_hex)
    ct = binascii.unhexlify(ciphertext_hex)
    
    # 拆分初始计数器（IV）和密文
    nonce = ct[:16]
    ciphertext = ct[16:]
    
    # CTR 解密（无需填充）
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=0)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext.decode('utf-8')

# ===================== 测试第1~4题 =====================
if __name__ == '__main__':
    # 第1题 CBC
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题答案：", aes_cbc_decrypt(key1, ct1))

    # 第2题 CBC
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题答案：", aes_cbc_decrypt(key1, ct2))

    # 第3题 CTR
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题答案：", aes_ctr_decrypt(key2, ct3))

    # 第4题 CTR
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题答案：", aes_ctr_decrypt(key2, ct4))