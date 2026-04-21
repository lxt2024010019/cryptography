from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def aes_cbc_decrypt(key_hex, ciphertext_hex):
    """
    AES CBC 模式解密（自主实现工作模式）
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节为IV）
    :return: 明文字符串
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 2. 拆分 IV（前16字节）和 实际密文
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    
    # 3. 初始化 AES-ECB 解密器
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    plaintext_blocks = []
    
    # 4. CBC 解密核心逻辑
    prev_cipher_block = iv
    for block in blocks:
        # ECB 解密当前密文块
        decrypted_block = cipher.decrypt(block)
        # 与前一个密文块/IV异或得到明文
        plain_block = bytes([x ^ y for x, y in zip(decrypted_block, prev_cipher_block)])
        plaintext_blocks.append(plain_block)
        prev_cipher_block = block
    
    # 5. 拼接并去除 PKCS#5 填充
    plaintext = b''.join(plaintext_blocks)
    plaintext = unpad(plaintext, AES.block_size)
    
    return plaintext.decode('utf-8')

def aes_ctr_decrypt(key_hex, ciphertext_hex):
    """
    AES CTR 模式解密（自主实现工作模式）
    :param key_hex: 十六进制密钥
    :param ciphertext_hex: 十六进制密文（前16字节为初始计数器）
    :return: 明文字符串
    """
    # 1. 十六进制转字节
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 2. 拆分初始计数器 IV（前16字节）和 实际密文
    nonce = ciphertext[:16]
    ct = ciphertext[16:]
    
    # 3. 初始化 AES-ECB 加密器（CTR 始终用加密）
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = []
    counter = 0
    
    # 4. CTR 解密核心逻辑：生成密钥流 + 异或
    for i in range(0, len(ct), 16):
        # 生成当前计数器值：nonce + 小端计数器
        current_counter = nonce[:-4] + (counter).to_bytes(4, byteorder='little')
        counter += 1
        
        # 加密计数器得到密钥流块
        keystream = cipher.encrypt(current_counter)
        
        # 取对应长度密文块
        ct_block = ct[i:i+16]
        
        # 密钥流与密文异或得到明文
        plain_block = bytes([x ^ y for x, y in zip(ct_block, keystream)])
        plaintext.append(plain_block)
    
    return b''.join(plaintext).decode('utf-8')

# ===================== 测试 4 道题目 =====================
if __name__ == '__main__':
    print("========== CBC 模式第 1 题 ==========")
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print(aes_cbc_decrypt(key1, ct1))

    print("\n========== CBC 模式第 2 题 ==========")
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print(aes_cbc_decrypt(key1, ct2))

    print("\n========== CTR 模式第 3 题 ==========")
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print(aes_ctr_decrypt(key2, ct3))

    print("\n========== CTR 模式第 4 题 ==========")
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print(aes_ctr_decrypt(key2, ct4))