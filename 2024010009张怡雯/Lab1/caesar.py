"""
凯撒密码穷举破解程序
实验任务：解密密文 "NUFECMWBYUJMBIQGYNBYWIXY"
"""

def caesar_decrypt(ciphertext, shift):
    """
    凯撒密码解密函数
    :param ciphertext: 密文字符串（大写字母）
    :param shift: 移位数（1-25）
    :return: 解密后的明文字符串
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():  # 只处理字母字符
            # 将字母转换回明文（逆向移位）
            # ord('A') = 65, 通过减去65得到0-25的数值
            decrypted = chr((ord(char) - 65 - shift) % 26 + 65)
            plaintext += decrypted
        else:
            plaintext += char  # 非字母字符保持不变
    return plaintext

def main():
    # 密文
    ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"
    
    print("=" * 50)
    print("凯撒密码穷举破解")
    print(f"密文: {ciphertext}")
    print("=" * 50)
    
    # 穷举所有可能的密钥 (1-25)
    for k in range(1, 26):
        plaintext = caesar_decrypt(ciphertext, k)
        print(f"k={k:2d}: {plaintext}")
    
    print("=" * 50)

    #添加暂停，等待用户输入
    input("按回车键退出")

if __name__ == "__main__":
    main()