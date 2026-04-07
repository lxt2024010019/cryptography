# Lab1：穷举法破译凯撒密码 实验报告
姓名：胡再冉
学号：2024010015

## 一、实验目的
1.  掌握凯撒密码的基本解密原理。
2.  学会使用穷举法暴力破解凯撒密码。
3.  理解古典密码的安全性缺陷。

## 二、实验原理
凯撒密码通过将字母表中的字母向前/向后移动固定位数（密钥k）实现加密。
解密时反向移动位数，通过遍历1-25所有可能的密钥，即可找到有意义的明文。

## 三、实验源代码
```python
def caesar_decrypt(cipher, k):
    plaintext = ""
    for char in cipher:
        if char.isupper():
            shifted = ord(char) - k
            # 修正：确保变量名拼写一致，不要打错字
            if shifted < ord('A'):
                shifted += 26
            plaintext += chr(shifted)
        else:
            plaintext += char
    return plaintext

ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

for k in range(1, 26):
    result = caesar_decrypt(ciphertext, k)
    print(f"k={k:2d}: {result}")
    ```
## 四、实验结果分析
1.  **正确密钥**：k=20
2.  **解密后明文**：TALKISCHEAPSHOWMETHECODE
3.  **断句与翻译**：
    - 断句：TALK IS CHEAP SHOW ME THE CODE
    - 翻译：空谈无益，亮出代码。
4.  **判断方法**：遍历所有密钥后，只有k=20对应的解密结果是有意义的英文句子，符合日常语言逻辑，因此判定为正确明文。

## 五、实验总结
本次凯撒密码解密实验，我收获了三点核心内容：
1.  掌握了凯撒密码的原理与Python实现方法，学会用 `ord()`、`chr()` 处理字符转换。
2.  理解了暴力破解的思路，通过遍历密钥筛选有意义的明文。
3.  锻炼了从大量信息中筛选有效内容的能力，也体会到编程细节（如边界判断）的重要性。
