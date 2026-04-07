# caesar.py
# 凯撒密码穷举破解实现

def caesar_decrypt(ciphertext, k):
    """
    凯撒密码解密函数
    :param ciphertext: 密文（大写英文字母）
    :param k: 密钥（1~25）
    :return: 解密后的明文
    """
    plaintext = ""
    for c in ciphertext:
        if c.isalpha() and c.isupper():
            # 大写字母解密：向前移动k位，模26保证循环
            shifted = ord(c) - k
            if shifted < ord('A'):
                shifted += 26
            plaintext += chr(shifted)
        else:
            # 非大写字母直接保留
            plaintext += c
    return plaintext

if __name__ == "__main__":
    # 给定的密文
    ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"
    print("穷举所有可能的密钥k（1~25），解密结果如下：\n")
    # 遍历所有密钥
    for k in range(1, 26):
        plaintext = caesar_decrypt(ciphertext, k)
        print(f"k={k} : {plaintext}")