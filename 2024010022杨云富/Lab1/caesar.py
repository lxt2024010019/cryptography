def caesar_decrypt(ciphertext, shift):
    """凯撒密码解密函数
    :param ciphertext: 待解密密文
    :param shift: 偏移量（密钥k）
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha() and char.isupper():
            # 对大写字母进行反向偏移解密
            plaintext += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
        else:
            # 非字母字符保持不变
            plaintext += char
    return plaintext

if __name__ == "__main__":
    # 题目给定的正确密文
    cipher_text = "NUFECMWBYUJMBIQGYNBYWIXY"
    
    print("凯撒密码穷举解密结果（k=1~25）：")
    print("=" * 60)
    
    # 遍历所有可能的密钥，输出全部解密结果
    for k in range(1, 26):
        decrypt_result = caesar_decrypt(cipher_text, k)
        print(f"k={k:<2} : {decrypt_result}")
    
    print("=" * 60)
    # 正确破译结果
    print("正确破译结果：")
    print(f"密钥k = 20")
    print(f"明文 = {caesar_decrypt(cipher_text, 20)}")
