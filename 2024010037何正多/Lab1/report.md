# 一、实验源代码

```python
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
    print(f"k={key:<2} : {decrypted_text}")
```
# 二、实验分析

```
1. 正确的密钥 k 是：20"
2. 解密后的明文是：TALKISCHEAPSHOWMETHECODE
3. 判断方法：通过观察和语言习惯，当密钥为 20 时，解密结果为 'TALKISCHEAPSHOWMETHECODE'，这是一个有意义的英文句子（虽然中间没有空格，但内容符合常见的测试明文）。其他密钥解密出的字符串大多是无意义的乱码，只有这个密钥对应的结果具有明确的语义。