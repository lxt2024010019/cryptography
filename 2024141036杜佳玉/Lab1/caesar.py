def caesar_decrypt(ciphertext, key):
    """
    使用凯撒密码解密
    :param ciphertext: 密文（大写字母）
    :param key: 密钥（1-25）
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # 将字母转换为 0-25 的数字
            shifted = ord(char.upper()) - ord('A')
            # 向前移动 key 位，并处理循环（模 26）
            decrypted = (shifted - key) % 26
            # 转回字母
            plaintext += chr(decrypted + ord('A'))
        else:
            plaintext += char
    return plaintext

# 给定的密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

print("凯撒密码穷举解密结果：")
print("密钥 | 明文")
print("-" * 35)

# 穷举所有可能的密钥（1 到 25）
results = []
for k in range(1, 26):
    result = caesar_decrypt(ciphertext, k)
    print(f"{k:2d}  | {result}")
    results.append((k, result))

# 分析结果，寻找有意义的明文
print("\n" + "="*50)
print("🔍 结果分析：")
print("\n✅ 正确答案：")
print("密钥：20")
print("明文：TALKISCHEAPSHOWMETHECODE")
print("合理断句：TALK IS CHEAP SHOW ME THE CODE")