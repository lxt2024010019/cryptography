# 一、实验目的

通过实现凯撒密码的暴力破解算法，理解对称加密中密钥空间有限的安全隐患，掌握穷举攻击的基本思想与实现方法。

## 二、实验原理

凯撒密码是一种经典的替换加密算法，通过将明文字母表中每个字母向后（或向前）移动固定位数 k（密钥）实现加密/解密。

- 加密：明文字母 → 向后移动 k 位 → 密文字母
- 解密：密文字母 → 向前移动 k 位（等价于向后移动 26-k 位）→ 明文字母
- 密钥 k 取值范围为 1~25（k=0 或 k=26 等价于无加密），因此可通过穷举所有密钥实现暴力破解。

## 三、核心代码实现

### 凯撒密码暴力破解程序

```python
cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

def caesar_decrypt(ciphertext, k):
    """
    凯撒密码解密函数
    :param ciphertext: 待解密的密文（仅支持大写英文字母）
    :param k: 解密密钥（1~25）
    :return: 解密后的明文
    """
    plaintext = []
    for c in ciphertext:
        if c.isalpha():
            # 大写字母处理：向前移动k位，模26保证字母循环
            if c.isupper():
                shifted = ord(c) - k
                if shifted < ord('A'):
                    shifted += 26
                plaintext.append(chr(shifted))
            # 小写字母处理（本题无小写，可兼容扩展）
            else:
                shifted = ord(c) - k
                if shifted < ord('a'):
                    shifted += 26
                plaintext.append(chr(shifted))
        else:
            # 非字母字符直接保留
            plaintext.append(c)
    return ''.join(plaintext)

# 遍历所有可能密钥(1~25)，按实验要求格式输出
for k in range(1, 26):
    result = caesar_decrypt(cipher, k)
    print(f"k={k} : {result}")
四、实验结果
程序运行后输出所有 25 种可能的解密结果：
plaintext
密钥 k= 1 → 解密结果: MTEDBLVAXTILAHPFXMAXVHWX
密钥 k= 2 → 解密结果: LSDCAKUZWSHKZGOEWLZWUGVW
密钥 k= 3 → 解密结果: KRCBZJTYVRGJYFNDVKYVTFUV
密钥 k= 4 → 解密结果: JQBAYISXUQFIXEMCUJXUSETU
密钥 k= 5 → 解密结果: IPAZXHRWTPEHWDLBTIWTRDST
密钥 k= 6 → 解密结果: HOZYWGQVSODGVCKASHVSQCRS
密钥 k= 7 → 解密结果: GNYXVFPURNCFUBJZRGURPBQR
密钥 k= 8 → 解密结果: FMXWUEOTQMBETAIYQFTQOAPQ
密钥 k= 9 → 解密结果: ELWVTDNSPLADSZHXPESPNZOP
密钥 k=10 → 解密结果: DKVUSCMROKZCRYGWODROMYNO
密钥 k=11 → 解密结果: CJUTRBLQNJYBQXFVNCQNLXMN
密钥 k=12 → 解密结果: BITSQAKPMIXAPWEUMBPMKWLM
密钥 k=13 → 解密结果: AHSRPZJOLHWZOVDTLAOLJVKL
密钥 k=14 → 解密结果: ZGRQOYINKGVYNUCSKZNKIUJK
密钥 k=15 → 解密结果: YFQPNXHMJFUXMTBRJYMJHTIJ
密钥 k=16 → 解密结果: XEPOMWGLIETWLSAQIXLIGSHI
密钥 k=17 → 解密结果: WDONLVFKHDSVKRZPHWKHFRGH
密钥 k=18 → 解密结果: VCNMKUEJGCRUJQYOGVJGEQFG
密钥 k=19 → 解密结果: UBMLJTDIFBQTIPXNFUIFDPEF
密钥 k=20 → 解密结果: TALKISCHEAPSHOWMETHECODE
密钥 k=21 → 解密结果: SZKJHRBGDZORGNVLDSGDBNCD
结果分析:
正确的密钥 k 是多少？
正确密钥为 k = 20。
解密后的明文是什么？
解密后的明文为：密钥 k=20 → 解密结果: TALKISCHEAPSHOWMETHECODE
（实际为有意义的英文句子，符合自然语言语义）。
句子为：TALK IS CHEAP SHOW ME THE CODE
语义为：空谈无益，亮出代码。
判断正确明文的依据
凯撒密码密钥空间仅为 1~25，可穷举所有可能。
只有包含有意义英文单词、符合自然语言语法的结果才是正确明文。
对比 25 组结果，仅 k=19 对应的解密结果为可读英文，其余均为无意义字母组合，因此判定该结果为正确明文。
五、实验总结
本次实验成功用 Python 实现了凯撒密码的暴力破解，验证了穷举攻击的可行性。
明确了凯撒密码的核心逻辑是字母移位，也认识到其密钥空间小，安全性极低，易被暴力破解。
掌握了遍历密钥尝试解密、通过语义判断正确结果的核心思路，为后续学习更安全的加密算法打下基础。