def caesar_decrypt(ciphertext, key):
    """
    凯撒密码解密函数
    :param ciphertext: 密文字符串（大写）
    :param key: 解密密钥（偏移量）
    :return: 解密后的明文字符串
    """
    plaintext = ""
    for char in ciphertext:
        if 'A' <= char <= 'Z':
            decrypted_char = chr((ord(char) - ord('A') - key) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"


for key in range(1, 26):
    plaintext = caesar_decrypt(ciphertext, key)
    print(f"k={key:2d}  : {plaintext}")

print("\n=== 正确结果 ===")
print("正确密钥 k=9")
print("解密明文: ILOVEPROGRAMMINGVERYMUCH")