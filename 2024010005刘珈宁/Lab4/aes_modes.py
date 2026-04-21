#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES CBC 和 CTR 模式加解密实现
学号姓名: 2024010005刘珈宁
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii


def aes_cbc_decrypt(key_hex: str, cipher_hex: str) -> str:
    """
    AES CBC 模式解密
    参数:
        key_hex: 十六进制字符串格式的密钥
        cipher_hex: 十六进制字符串格式的密文，前16字节为IV
    返回:
        解密后的明文字符串
    
    解题步骤解析：
    1. 十六进制字符串转换为字节：binascii.unhexlify()函数将十六进制字符串转换为字节数据
    2. 提取IV：CBC模式中，密文的前16字节是初始化向量(IV)
    3. 分离实际密文：去除IV后的部分才是需要解密的密文
    4. 创建AES CBC解密器：使用密钥和IV创建解密器
    5. 执行解密：对密文进行AES CBC解密
    6. 去除填充：CBC模式使用PKCS7填充，需要去除填充字节
    7. 解码为字符串：将解密后的字节转换为UTF-8字符串
    """
    
    # 步骤1: 将十六进制字符串转换为字节
    # binascii.unhexlify将"140b41b2..."这样的十六进制字符串转换为字节数据
    key = binascii.unhexlify(key_hex)
    cipher_bytes = binascii.unhexlify(cipher_hex)
    
    # 步骤2: 提取前16字节作为IV
    # CBC模式中，初始化向量(IV)用于第一个明文块的异或操作
    iv = cipher_bytes[:16]
    
    # 步骤3: 剩余部分为实际需要解密的密文
    ciphertext = cipher_bytes[16:]
    
    # 步骤4: 创建AES CBC解密器
    # 使用MODE_CBC模式，需要提供密钥和IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 步骤5: 执行解密
    # CBC解密流程：先AES解密，然后与前一个密文块（或IV）异或
    decrypted = cipher.decrypt(ciphertext)
    
    # 步骤6: 去除PKCS7填充
    # PKCS7填充：在明文末尾添加n个值为n的字节，n为填充字节数
    plaintext = unpad(decrypted, 16)
    
    # 步骤7: 将字节解码为字符串返回
    return plaintext.decode('utf-8')


def aes_ctr_decrypt(key_hex: str, cipher_hex: str) -> str:
    """
    AES CTR 模式解密
    参数:
        key_hex: 十六进制字符串格式的密钥
        cipher_hex: 十六进制字符串格式的密文，前16字节为初始计数器值
    返回:
        解密后的明文字符串
    
    解题步骤解析：
    1. 十六进制字符串转换为字节
    2. 提取初始计数器值：CTR模式中，密文的前16字节是初始计数器值
    3. 分离实际密文
    4. 创建AES ECB加密器：CTR模式使用ECB模式加密计数器值生成密钥流
    5. 逐块解密：
       a. 计算当前计数器值 = 初始计数器值 + 块索引
       b. 将计数器值转换为16字节
       c. 使用AES ECB加密计数器值得到密钥流
       d. 密钥流与密文块异或得到明文块
    6. 合并所有明文块并解码
    """
    
    # 步骤1: 将十六进制字符串转换为字节
    key = binascii.unhexlify(key_hex)
    cipher_bytes = binascii.unhexlify(cipher_hex)
    
    # 步骤2: 提取前16字节作为初始计数器值
    # CTR模式使用计数器值生成密钥流，第一个计数器值在密文中
    initial_counter = cipher_bytes[:16]
    
    # 步骤3: 剩余部分为实际需要解密的密文
    ciphertext = cipher_bytes[16:]
    
    # 步骤4: 创建AES ECB加密器
    # CTR模式的核心：使用AES ECB加密计数器值来生成密钥流
    aes_ecb = AES.new(key, AES.MODE_ECB)
    
    # 步骤5: 初始化明文字节串
    plaintext_bytes = b""
    
    # 步骤6: 逐块解密，每块16字节
    for i in range(0, len(ciphertext), 16):
        # 步骤6a: 计算当前计数器值 = 初始值 + 块索引
        # 块索引 = 当前字节位置 ÷ 块大小(16)
        current_counter = int.from_bytes(initial_counter, 'big') + (i // 16)
        
        # 步骤6b: 将计数器值转换为16字节
        # to_bytes(16, 'big')将整数转换为大端字节序的16字节
        counter_bytes = current_counter.to_bytes(16, 'big')
        
        # 步骤6c: 加密计数器得到密钥流
        # 使用AES ECB模式加密计数器值，生成伪随机密钥流
        keystream = aes_ecb.encrypt(counter_bytes)
        
        # 步骤6d: 获取当前密文块
        cipher_block = ciphertext[i:i + 16]
        
        # 步骤6e: 密钥流与密文异或得到明文
        # 只取需要的字节数（最后一块可能不足16字节）
        keystream_block = keystream[:len(cipher_block)]
        
        # XOR操作：流密码的核心，密钥流 ⊕ 密文 = 明文
        plaintext_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
        
        # 步骤6f: 将解密块添加到结果中
        plaintext_bytes += plaintext_block
    
    # 步骤7: 将解密后的字节解码为字符串返回
    # CTR模式不需要填充，直接解码即可
    return plaintext_bytes.decode('utf-8')


def solve_all_questions():
    """解答Lab4中的所有问题"""
    print("=== AES CBC 和 CTR 模式解密实验解答 ===")
    print("=" * 60)
    
    # 第1题：CBC模式解密
    print("\n第1题：CBC模式解密")
    print("-" * 40)
    print("解题思路：")
    print("1. 密钥和密文都是十六进制字符串，需要先转换为字节")
    print("2. CBC模式密文的前16字节是IV，需要提取出来")
    print("3. 使用AES.new()创建CBC解密器，传入密钥和IV")
    print("4. 解密后使用unpad()去除PKCS7填充")
    print("5. 将结果解码为UTF-8字符串")
    print("-" * 40)
    
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    
    plaintext1 = aes_cbc_decrypt(key1, cipher1)
    print(f"密钥: {key1}")
    print(f"密文长度: {len(cipher1)//2} 字节（{len(cipher1)//2 - 16}字节实际密文 + 16字节IV）")
    print(f"解密结果: {plaintext1}")
    
    # 第2题：CBC模式解密
    print("\n第2题：CBC模式解密")
    print("-" * 40)
    print("解题思路：")
    print("1. 与第1题使用相同的密钥")
    print("2. 解密步骤与第1题完全相同")
    print("3. 注意CBC模式的特点：每个密文块解密后与前一个密文块（或IV）异或")
    print("4. 需要去除PKCS7填充，填充字节数由最后一个字节的值决定")
    print("-" * 40)
    
    key2 = "140b41b22a29beb4061bda66b6747e14"  
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    
    plaintext2 = aes_cbc_decrypt(key2, cipher2)
    print(f"密钥: {key2}")
    print(f"密文长度: {len(cipher2)//2} 字节（{len(cipher2)//2 - 16}字节实际密文 + 16字节IV）")
    print(f"解密结果: {plaintext2}")
    
    # 第3题：CTR模式解密
    print("\n第3题：CTR模式解密")
    print("-" * 40)
    print("解题思路：")
    print("1. CTR模式将分组密码转换为流密码")
    print("2. 密文的前16字节是初始计数器值，不是IV")
    print("3. 对递增的计数器值进行AES加密，生成密钥流")
    print("4. 密钥流与密文异或得到明文")
    print("5. CTR模式不需要填充，解密后直接就是明文")
    print("-" * 40)
    
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    
    plaintext3 = aes_ctr_decrypt(key3, cipher3)
    print(f"密钥: {key3}")
    print(f"密文长度: {len(cipher3)//2} 字节（{len(cipher3)//2 - 16}字节实际密文 + 16字节初始计数器）")
    print(f"解密结果: {plaintext3}")
    
    # 第4题：CTR模式解密
    print("\n第4题：CTR模式解密")
    print("-" * 40)
    print("解题思路：")
    print("1. 与第3题使用相同的密钥")
    print("2. 解密步骤与第3题完全相同")
    print("3. 注意计数器递增：每个块使用初始计数器值 + 块索引")
    print("4. CTR模式支持并行计算，且不需要填充")
    print("-" * 40)
    
    key4 = "36f18357be4dbd77f050515c73fcf9f2" 
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    
    plaintext4 = aes_ctr_decrypt(key4, cipher4)
    print(f"密钥: {key4}")
    print(f"密文长度: {len(cipher4)//2} 字节（{len(cipher4)//2 - 16}字节实际密文 + 16字节初始计数器）")
    print(f"解密结果: {plaintext4}")
    
    print("\n" + "=" * 60)
    print("实验总结：")
    print("1. CBC模式：需要IV，需要填充，解密时先解密后异或")
    print("2. CTR模式：需要初始计数器，不需要填充，将分组密码转为流密码")
    print("3. 两种模式都将IV/计数器放在密文前部传输")
    print("4. 本实验成功实现了两种模式的解密功能")
    print("=" * 60)


if __name__ == "__main__":
    # 检查依赖库是否安装
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        print("✓ 依赖库检查通过：pycryptodome 已安装")
    except ImportError:
        print("错误：需要安装 pycryptodome 库")
        print("请运行: pip install pycryptodome")
        print("然后重新运行此程序")
        exit(1)
    
    # 解答所有问题
    solve_all_questions()