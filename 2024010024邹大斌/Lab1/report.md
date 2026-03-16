 凯撒密码实验报告

一、实验目的
掌握凯撒密码的加密与解密原理，使用暴力破解法枚举所有可能的密钥，还原出有意义的明文。

二、实验原理
凯撒密码是一种替换加密算法。通过将字母表中的每个字母向后移动固定位数 $k$（密钥）实现加密；解密时则向前移动 $k$ 位。
由于密钥 $k$ 的取值范围仅为 1~25，因此可以通过穷举法枚举所有密钥，逐一解密并分析结果是否为有意义的自然语言文本。

三、实验步骤
1. 编写凯撒解密函数 `caesar_decrypt`，实现对给定密文和密钥的解密逻辑。
2. 遍历密钥范围 1~25，输出每种密钥对应的解密结果。
3. 分析所有 25 种结果，识别出唯一符合英文语义的明文。

 四、实验结果
- 正确密钥 k：20
- 解密后的明文：TALKISCHEAPSHOWMETHECODE
- **判断依据**：
  遍历所有 25 个密钥后，仅 $k=20$ 对应的解密结果符合英文自然语言特征。其余密钥对应的结果均为无意义的随机字母组合，因此可确定 $k=20$ 为正确密钥。
五、代码实现
def caesar_decrypt(ciphertext, shift):
    """凯撒密码解密函数
    :param ciphertext: 待解密密文
    :param shift: 偏移量（密钥k）
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha() and char.isupper():
          
            plaintext += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
        else:
            
            plaintext += char
    return plaintext

if __name__ == "__main__":
    
    cipher_text = "NUFECMWBYUJMBIQGYNBYWIXY"
    
    print("凯撒密码穷举解密结果（k=1~25）：")
    print("=" * 60)
    
    
    for k in range(1, 26):
        decrypt_result = caesar_decrypt(cipher_text, k)
        print(f"k={k:<2} : {decrypt_result}")
    
    print("=" * 60)
   
    print("✅ 正确破译结果：")
    print(f"密钥k = 20")
    print(f"明文 = {caesar_decrypt(cipher_text, 20)}")