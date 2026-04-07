def caesar_decrypt(ciphertext, key):
    """
    凯撒密码解密函数
    :param ciphertext: 密文
    :param key: 密钥 (1-25)
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isupper():  # 只考虑大写字母
            # 解密公式: (ord(char) - ord('A') - key) % 26 + ord('A')
            # 注意：这里使用 -key，因为是解密（加密是 +key）
            decrypted_char = chr((ord(char) - ord('A') - key) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char  # 非字母字符保持不变
    return plaintext

# 密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

print("开始穷举凯撒密码密钥...\n")
print(f"{'密钥':<5} {'解密结果':<40}")
print("-" * 50)

# 枚举所有可能的密钥 (1~25)
for key in range(1, 26):
    decrypted_text = caesar_decrypt(ciphertext, key)
    print(f"{key:<5} {decrypted_text}")

print("\n" + "="*50)
print("请检查上面的解密结果，寻找有意义的英文单词或短语。")
print("正确的密钥和明文应该是那个看起来像正常语言的字符串。")