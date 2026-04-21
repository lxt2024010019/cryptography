# aes_modes.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import os

def aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES ECB 模式加密
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES ECB 模式解密
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def aes_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES CBC 模式解密
    参数:
        key: 密钥（16/24/32字节）
        ciphertext: 密文（包含16字节IV）
    返回:
        解密后的明文
    """
    # 提取IV（前16字节）
    iv = ciphertext[:16]
    ciphertext_blocks = ciphertext[16:]
    
    # 计算分组数
    block_size = 16
    num_blocks = len(ciphertext_blocks) // block_size
    
    # 创建AES ECB解密器
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 存储解密结果
    plaintext_blocks = []
    
    # 前一个密文块（第一个块与IV异或）
    prev_cipher_block = iv
    
    # 解密每个块
    for i in range(num_blocks):
        # 获取当前密文块
        start = i * block_size
        end = start + block_size
        cipher_block = ciphertext_blocks[start:end]
        
        # 使用AES ECB解密当前密文块
        decrypted_block = cipher.decrypt(cipher_block)
        
        # 与前一个密文块（或IV）异或得到明文块
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_cipher_block))
        plaintext_blocks.append(plaintext_block)
        
        # 更新前一个密文块
        prev_cipher_block = cipher_block
    
    # 合并所有明文块
    plaintext = b''.join(plaintext_blocks)
    
    # 移除PKCS#5填充
    try:
        plaintext = unpad(plaintext, block_size, style='pkcs7')
    except ValueError as e:
        # 如果填充不正确，返回未去除填充的结果
        print(f"Warning: Padding error: {e}")
    
    return plaintext

def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES CBC 模式加密
    参数:
        key: 密钥（16/24/32字节）
        plaintext: 明文
    返回:
        密文（包含IV）
    """
    # 生成随机IV
    iv = os.urandom(16)
    
    # PKCS#5填充
    block_size = 16
    padding_length = block_size - len(plaintext) % block_size
    padding = bytes([padding_length] * padding_length)
    padded_plaintext = plaintext + padding
    
    # 计算分组数
    num_blocks = len(padded_plaintext) // block_size
    
    # 创建AES ECB加密器
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 存储加密结果
    ciphertext_blocks = []
    
    # 前一个密文块（第一个块与IV异或）
    prev_cipher_block = iv
    
    # 加密每个块
    for i in range(num_blocks):
        # 获取当前明文块
        start = i * block_size
        end = start + block_size
        plaintext_block = padded_plaintext[start:end]
        
        # 与前一个密文块（或IV）异或
        xor_block = bytes(x ^ y for x, y in zip(plaintext_block, prev_cipher_block))
        
        # 使用AES ECB加密
        cipher_block = cipher.encrypt(xor_block)
        ciphertext_blocks.append(cipher_block)
        
        # 更新前一个密文块
        prev_cipher_block = cipher_block
    
    # 合并IV和所有密文块
    ciphertext = iv + b''.join(ciphertext_blocks)
    
    return ciphertext

def aes_ctr_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES CTR 模式解密/加密
    注意：CTR模式下加密和解密是相同的操作
    参数:
        key: 密钥（16/24/32字节）
        ciphertext: 密文（包含16字节计数器初始值）
    返回:
        解密后的明文
    """
    # 提取计数器初始值（前16字节）
    nonce = ciphertext[:16]
    ciphertext_data = ciphertext[16:]
    
    # 创建AES ECB加密器
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 存储解密结果
    plaintext = []
    
    # 对每个16字节块进行处理
    for i in range(0, len(ciphertext_data), 16):
        # 获取当前计数器值
        # 注意：在真实实现中，需要正确处理大数加法
        counter = int.from_bytes(nonce, 'big')
        counter += i // 16
        counter_bytes = counter.to_bytes(16, 'big')
        
        # 加密计数器值生成密钥流
        keystream = cipher.encrypt(counter_bytes)
        
        # 获取对应的密文块
        cipher_block = ciphertext_data[i:i+16]
        
        # 密钥流与密文异或得到明文
        plaintext_block = bytes(x ^ y for x, y in zip(cipher_block, keystream[:len(cipher_block)]))
        plaintext.append(plaintext_block)
    
    # 合并所有明文块
    return b''.join(plaintext)

def aes_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES CTR 模式加密
    注意：CTR模式下加密和解密是相同的操作
    参数:
        key: 密钥（16/24/32字节）
        plaintext: 明文
    返回:
        密文（包含计数器初始值）
    """
    # 生成随机计数器初始值
    nonce = os.urandom(16)
    
    # 创建AES ECB加密器
    cipher = AES.new(key, AES.MODE_ECB)
    
    # 存储加密结果
    ciphertext = []
    
    # 对每个16字节块进行处理
    for i in range(0, len(plaintext), 16):
        # 获取当前计数器值
        counter = int.from_bytes(nonce, 'big')
        counter += i // 16
        counter_bytes = counter.to_bytes(16, 'big')
        
        # 加密计数器值生成密钥流
        keystream = cipher.encrypt(counter_bytes)
        
        # 获取对应的明文块
        plaintext_block = plaintext[i:i+16]
        
        # 密钥流与明文异或得到密文
        ciphertext_block = bytes(x ^ y for x, y in zip(plaintext_block, keystream[:len(plaintext_block)]))
        ciphertext.append(ciphertext_block)
    
    # 合并计数器初始值和所有密文块
    return nonce + b''.join(ciphertext)

def hex_to_bytes(hex_str: str) -> bytes:
    """
    将十六进制字符串转换为字节
    """
    return bytes.fromhex(hex_str)

def test_decryption():
    """
    测试解密函数
    """
    print("=" * 60)
    print("AES CBC/CTR 模式解密测试")
    print("=" * 60)
    
    # 第1题：CBC模式解密
    print("\n第1题：CBC模式解密")
    key1 = hex_to_bytes("140b41b22a29beb4061bda66b6747e14")
    ciphertext1 = hex_to_bytes("4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81")
    plaintext1 = aes_cbc_decrypt(key1, ciphertext1)
    print(f"密钥: 140b41b22a29beb4061bda66b6747e14")
    print(f"密文: 4ca00ff4c898d61e1edbf1800618fb28...")
    print(f"解密结果: {plaintext1.decode('utf-8')}")
    
    # 第2题：CBC模式解密
    print("\n第2题：CBC模式解密")
    key2 = hex_to_bytes("140b41b22a29beb4061bda66b6747e14")
    ciphertext2 = hex_to_bytes("5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253")
    plaintext2 = aes_cbc_decrypt(key2, ciphertext2)
    print(f"密钥: 140b41b22a29beb4061bda66b6747e14")
    print(f"密文: 5b68629feb8606f9a6667670b75b38a5...")
    print(f"解密结果: {plaintext2.decode('utf-8')}")
    
    # 第3题：CTR模式解密
    print("\n第3题：CTR模式解密")
    key3 = hex_to_bytes("36f18357be4dbd77f050515c73fcf9f2")
    ciphertext3 = hex_to_bytes("69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329")
    plaintext3 = aes_ctr_decrypt(key3, ciphertext3)
    print(f"密钥: 36f18357be4dbd77f050515c73fcf9f2")
    print(f"密文: 69dda8455c7dd4254bf353b773304eec...")
    print(f"解密结果: {plaintext3.decode('utf-8')}")
    
    # 第4题：CTR模式解密
    print("\n第4题：CTR模式解密")
    key4 = hex_to_bytes("36f18357be4dbd77f050515c73fcf9f2")
    ciphertext4 = hex_to_bytes("770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451")
    plaintext4 = aes_ctr_decrypt(key4, ciphertext4)
    print(f"密钥: 36f18357be4dbd77f050515c73fcf9f2")
    print(f"密文: 770b80259ec33beb2561358a9f2dc617...")
    print(f"解密结果: {plaintext4.decode('utf-8')}")
    
    print("\n" + "=" * 60)
    print("所有测试完成！")
    print("=" * 60)

def test_encryption_decryption():
    """
    测试加密解密功能
    """
    print("\n" + "=" * 60)
    print("加密解密完整性测试")
    print("=" * 60)
    
    # 测试CBC模式
    print("\n1. CBC模式测试:")
    test_key = b"sixteenbytekey!!"  # 16字节密钥
    test_plaintext = b"This is a test message for CBC mode!"
    
    # 加密
    ciphertext = aes_cbc_encrypt(test_key, test_plaintext)
    print(f"原始明文: {test_plaintext}")
    print(f"加密后密文长度: {len(ciphertext)} 字节")
    
    # 解密
    decrypted = aes_cbc_decrypt(test_key, ciphertext)
    print(f"解密结果: {decrypted}")
    print(f"加解密一致性: {test_plaintext == decrypted}")
    
    # 测试CTR模式
    print("\n2. CTR模式测试:")
    test_plaintext2 = b"This is a test message for CTR mode!"
    
    # 加密
    ciphertext2 = aes_ctr_encrypt(test_key, test_plaintext2)
    print(f"原始明文: {test_plaintext2}")
    print(f"加密后密文长度: {len(ciphertext2)} 字节")
    
    # 解密
    decrypted2 = aes_ctr_decrypt(test_key, ciphertext2)
    print(f"解密结果: {decrypted2}")
    print(f"加解密一致性: {test_plaintext2 == decrypted2}")

if __name__ == "__main__":
    # 运行测试
    test_decryption()
    test_encryption_decryption()