# -*- coding: utf-8 -*-
# 穷举法破解凯撒密码 - 简洁版
# 功能：枚举密钥 k=1~25，对密文进行解密并输出所有结果

def caesar_decrypt(ciphertext, k):
    """凯撒解密函数（大写字母）"""
    return ''.join(
        chr((ord(c) - ord('A') - k) % 26 + ord('A')) if c.isalpha() else c
        for c in ciphertext
    )

# 密文
cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

print("穷举破解凯撒密码结果：")
for k in range(1, 26):
    print(f"k={k:<2d} : {caesar_decrypt(cipher, k)}")