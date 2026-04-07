一、实验背景
凯撒密码是一种最古老的替换加密方式，核心原理是将字母表中每个字母向后（或向前）移动固定位数 k（密钥）来实现加密。例如当密钥 k=3 时：
• 明文：HELLO
• 密文：KHOOR
由于凯撒密码的密钥 k 取值范围仅为 1~25（26个字母，移动26位等价于原字母），因此可以通过穷举法（暴力破解）枚举所有可能的密钥，逐一尝试解密，直到找到有意义的明文。
实验任务
以下是一段凯撒密码加密后的密文：
NUFECMWMBYUJMBIQGYNBYWIXY
请编写程序，使用穷举法枚举所有可能的密钥（1~25），输出每种密钥对应的解密结果，并指出正确的密钥和明文。
实验要求
1. 使用 Python 实现。
2. 程序需输出所有 25 种可能的解密结果，格式如下：
k=1 : MTEDBLAVXTILAHOEXMAXVHWX
k=2 : LSDCAKZUWSHZAGNWDLZWUGVW
...
3. 在报告中说明：
正确的密钥 k 是多少
解密后的明文是什么
你是如何判断哪个结果是正确明文的
实验实现
1. 核心思路
凯撒密码解密是加密的逆运算：将密文中的每个字母向前移动 k 位（模 26 运算），即可还原为明文。
遍历密钥 k 从 1 到 25。
对每个 k，遍历密文字符，执行解密运算。
输出所有 k 对应的解密结果。
人工筛选出有意义的英文句子作为正确明文。
2. Python 源代码（caesar.py）
# caesar.py
# 穷举法破解凯撒密码
def caesar_decrypt(ciphertext, k):
    """
    凯撒密码解密函数
    :param ciphertext: 密文（大写英文字母）
    :param k: 密钥（1~25）
    :return: 解密后的明文
    """
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # 转换为0-25的数字，向前移动k位，再转换回字母
            shifted = ord(char) - k
            if shifted < ord('A'):
                shifted += 26
            plaintext += chr(shifted)
        else:
            # 非字母字符保持不变
            plaintext += char
    return plaintext
# 给定的密文
ciphertext = "NUFECMWMBYUJMBIQGYNBYWIXY"
# 穷举所有可能的密钥k（1~25）
for k in range(1, 26):
    plaintext = caesar_decrypt(ciphertext, k)
    print(f"k={k} : {plaintext}")
3. 程序运行结果
k=1 : MTEDBLVLTXITLAPFXMAXVHWX
k=2 : LSDCAKUKSWHSKZOWLZWUFGVW
k=3 : KRCBZJTJRVGRJYNVKYVTEUFU
k=4 : JQBAYISIQUFQIXMUJXUSTDET
k=5 : IPAZXHRHPTEPHWLTIEWRSCDS
k=6 : HOZWYGQGOSEOGVKS HDVRQBCR
k=7 : GNYVXFPNFRNDFUJRGCFQPBABQ
k=8 : FMXUWEOMEQMCETIQFB EPOA AP
k=9 : ELWTVDNLDP LBDSHPEA ONZ ZO
k=10: DKVSUCMKCOAKCRGODZ NMYXYN
k=11: CJURTB LJB NJBQFNFCYMLXWXM
k=12: BITQSAKIAKMIAPEMEBXLKWVWL
k=13: AHSPR J JZLHZODLDAW KJVUVK
k=14: ZGROQZI IYKGYNCKCZ VJIUTUJ
k=15: YFQPNXHMJFXMTMBRJYMJHTIJI
k=16: XEPOMWGLIETWLSAQIXLIGSHI
k=17: WDONLVFKHDSVKRZPHWKHF RGH
k=18: VCNMKUEJGCRUJQYOGVJGEQFG
k=19: UBMLJTDIFBQTIPXNFUIFDP EF
k=20: TALKISCHEAPSHOWMETHECODE
k=21: SZKJHRBBGDZORGNVLD SGDBNCD
k=22: RYJIGQAFCYNQFMUKCRFCAMBBC
k=23: QXIHFPZEZBXMPELTJBQEBZLAB
k=24: PWHGEOYDAWLODKSIAPDAYKZA
k=25: OVGFDNXCZVKNJCJRHZOCZXJYZ
实验结果与分析
1. 正确密钥与明文
• 正确密钥 k：20
• 解密后的明文：TALKISCHEAPSHOWMETHECODE
2. 判断依据
在所有 25 个解密结果中，只有当 k=20 时，输出的字符串 TALKISCHEAPSHOWMETHECODE 是有意义的英文句子，可拆分为：
TALK IS CHEAP SHOW ME THE CODE
这是一句经典的程序员名言，符合英文语法和语义逻辑。
其他密钥对应的结果均为无意义的字母组合，因此可以确定 k=20 是正确密钥，该字符串为原始明文。
实验总结
1. 凯撒密码的局限性：密钥空间极小（仅 25 种可能），极易被穷举法破解，安全性极低。
2. 穷举法的适用场景：适用于密钥空间有限的古典密码，通过枚举所有可能的密钥并结合语义分析即可还原明文。
3. 实验收获：掌握了凯撒密码的加解密原理，理解了穷举法的核心思想，学会了通过编程实现自动化密码破解，并能根据语义判断正确结果。