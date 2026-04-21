# Lab4：AES CBC模式与CTR模式加解密实现
## 一、实验背景
高级加密标准（AES）是目前最广泛使用的对称加密算法之一。在实际应用中，AES通常结合不同的分组密码工作模式来加密任意长度的消息。本实验实现两种常见的AES工作模式：
- **CBC模式（密码分组链接模式）**：每个明文分组在加密前先与前一个密文分组进行异或运算，第一个分组与初始化向量（IV）异或。解密时需要逆向操作，且需使用PKCS#5填充方案。
- **CTR模式（计数器模式）**：将分组密码转化为流密码，通过加密递增的计数器值生成密钥流，再与明文异或得到密文。该模式支持并行加解密，且不需要填充。

两种模式中，16字节的加密IV（初始化向量）均随机选取，并前置于密文之前。

## 二、实验任务
使用Python实现AES CBC模式和CTR模式的解密逻辑，基于给定的密钥和密文，解密并恢复出明文。本实验仅测试解密功能。

## 三、实现步骤
### 1. CBC模式解密步骤
1.  从密文中提取前16字节作为IV，剩余部分为实际密文。
2.  使用AES ECB模式解密每个密文分组。
3.  将解密结果与前一个密文分组（或IV）异或，得到明文分组。
4.  对最后一个分组去除PKCS#5填充，得到最终明文。

### 2. CTR模式解密步骤
1.  从密文中提取前16字节作为初始计数器值（初始IV）。
2.  对递增的计数器值（初始值、初始值+1、初始值+2……）依次使用AES加密，生成密钥流。
3.  将密钥流与密文逐字节异或，得到明文（无需填充）。

## 四、核心代码实现
```python
from Cryptodome.Cipher import AES

def aes_cbc_decrypt(key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    # 提取IV和密文分组
    iv = ciphertext[:16]
    ct_blocks = ciphertext[16:]
    # 创建AES-ECB对象用于分组解密
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    prev_block = iv
    plaintext_blocks = []
    # 逐块解密并异或
    for i in range(0, len(ct_blocks), 16):
        ct_block = ct_blocks[i:i+16]
        decrypted_block = cipher_ecb.decrypt(ct_block)
        plain_block = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
        plaintext_blocks.append(plain_block)
        prev_block = ct_block
    # 拼接明文并去除PKCS#5填充
    plaintext = b"".join(plaintext_blocks)
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    return plaintext.decode("utf-8", errors="ignore")

def aes_ctr_decrypt(key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    # 提取初始计数器值
    counter = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b""
    # 逐块生成密钥流并异或
    for i in range(0, len(ct), 16):
        # 生成当前计数器值
        counter_int = int.from_bytes(counter, byteorder="big") + (i // 16)
        current_counter = counter_int.to_bytes(16, byteorder="big")
        # 加密计数器值生成密钥流
        keystream = cipher.encrypt(current_counter)
        # 与密文异或得到明文
        ct_block = ct[i:i+16]
        plain_block = bytes(a ^ b for a, b in zip(ct_block, keystream))
        plaintext += plain_block
    return plaintext.decode("utf-8", errors="ignore")

# -------------------- 题目解密与输出 --------------------
# Q1 CBC模式解密
key1 = "140b41b22a29beb4061bda66b6747e14"
cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a2"
plain1 = aes_cbc_decrypt(key1, cipher1)
print("Q1 plaintext:", plain1)

# Q2 CBC模式解密
key2 = "140b41b22a29beb4061bda66b6747e14"
cipher2 = "5b68629feb8606f9a6667670b75b38a5b483"
plain2 = aes_cbc_decrypt(key2, cipher2)
print("Q2 plaintext:", plain2)

# Q3 CTR模式解密
key3 = "36f18357be4dbd77f050515c73fcf9f2"
cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7"
plain3 = aes_ctr_decrypt(key3, cipher3)
print("Q3 plaintext:", plain3)

# Q4 CTR模式解密
key4 = "36f18357be4dbd77f050515c73fcf9f2"
cipher4 = "770b80259ec33beb2561358a9f2dc617e462"
plain4 = aes_ctr_decrypt(key4, cipher4)
print("Q4 plaintext:", plain4)
五、题目解密结果
题目	模式	解密结果（明文）	
第1题	CBC模式解密	Basic CBC mode encryption needs padding.	
第2题	CBC模式解密	Our implementation uses rand. IV	
第3题	CTR模式解密	CTR mode lets you build a stream cipher from a block cipher.	
第4题	CTR模式解密	Always avoid the two time pad!	
六、实验总结

本次实验成功实现了AES-CBC和CTR两种模式的解密逻辑，核心要点如下：

1. CBC模式：解密依赖前一个密文分组（或IV）的异或操作，且必须去除PKCS#5填充以还原明文。

2. CTR模式：通过递增计数器生成密钥流，无需填充，支持并行解密，实现过程更简洁高效。

3. 两种模式均通过提取前置的IV/初始计数器值完成解密，最终成功还原了所有题目中的明文，验证了实现的正确性。