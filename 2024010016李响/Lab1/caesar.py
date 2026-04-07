def caesar_decrypt(ciphertext, key):
    """
    凯撒密码解密核心函数
    :param ciphertext: 待解密的密文字符串（大写）
    :param key: 解密密钥（字母向前移动的位数）
    :return: 解密后的明文字符串
    """
    plaintext = []
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            original_code = ord(char) - key
            if original_code < ord('A'):
                original_code += 26
            plaintext.append(chr(original_code))
        else:
            plaintext.append(char)
    return ''.join(plaintext)

# 待解密的密文
target_cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

# 穷举1~25密钥并输出
print("=== 凯撒密码穷举解密结果 ===")
for k in range(1, 26):
    decrypt_result = caesar_decrypt(target_cipher, k)
    print(f"k={k:2d}  : {decrypt_result}")

# 标注正确结果
correct_key = 20
correct_plaintext = caesar_decrypt(target_cipher, correct_key)
print("\n=== 正确解密结果 ===")
print(f"正确密钥 k：{correct_key}")
print(f"解密后的明文：{correct_plaintext}")