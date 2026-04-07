def caesar_decrypt(ciphertext, key):
    """
    凯撒密码解密函数
    :param ciphertext: 密文
    :param key: 密钥 (偏移量)
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':  # 只考虑大写字母
            # 解密公式：明文字母 = (密文字母 - 偏移量 - 'A' + 26) % 26 + 'A'
            # 等价于：(密文字母 - 偏移量 - 65 + 26) % 26 + 65
            decrypted_char = chr(((ord(char) - ord('A') - key) % 26) + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char  # 非字母字符保持不变
    return plaintext

# 给定的密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

# 输出原始密文
print(f"原始密文: {ciphertext}\n")
print("开始穷举解密...\n")

# 穷举所有可能的密钥 (1~25)
for key in range(1, 26):
    decrypted_text = caesar_decrypt(ciphertext, key)
    print(f"密钥 {key:2d}: {decrypted_text}")
