Lab1：穷举法破解凯撒密码实验报告

一、实验背景

凯撒密码是最古老的经典代换密码之一，核心原理是将明文中的每个字母在字母表中向后移动固定位数 k（即密钥），从而实现加密。

例如，当密钥 k=3 时：

• 明文：HELLO

• 密文：KHOOR

由于凯撒密码的密钥空间极小，仅为 1~25（k=0 或 k=26 等价于无移位），因此可以通过穷举法（暴力破解）枚举所有可能的密钥，逐一尝试解密，最终筛选出有意义的明文，从而得到正确密钥。

二、实验任务

给定凯撒加密后的密文：
NUFECMWBYUJMBIQGYNBYWIXY
要求编写程序，使用穷举法枚举所有可能的密钥（1~25），输出每种密钥对应的解密结果，并指出正确的密钥和明文。

三、实验要求

1. 使用任意编程语言实现（推荐 Python）

2. 程序需输出所有 25 种可能的解密结果，格式为：
k=XX : 解密结果
3. 最终需指出正确密钥及对应的有意义明文

四、实验环境

• 操作系统：Windows（PowerShell / Git Bash 环境）

• 编程语言：Python 3.x

• 工具：VS Code 文本编辑器、命令行终端

五、实验原理与代码实现

1. 凯撒解密原理

对于大写字母，解密时需将密文字母向左移动 k 位，数学公式为：

\text{明文位置} = (\text{密文位置} - k) \mod 26

其中，字母 A-Z 对应位置 0-25，非字母字符保持不变。

2. 核心代码实现
# -*- coding: utf-8 -*-
# 穷举法破解凯撒密码 - 简洁版
# 功能：枚举密钥 k=1~25，对密文进行解密并输出所有结果

def caesar_decrypt(ciphertext, k):
    """凯撒解密函数（大写字母）"""
    return ''.join(
        chr((ord(c) - ord('A') - k) % 26 + ord('A')) if c.isalpha() else c
        for c in ciphertext
    )

# 实验给定密文
cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

print("穷举破解凯撒密码结果：")
for k in range(1, 26):
    print(f"k={k:<2d} : {caesar_decrypt(cipher, k)}")
3. 代码解析
• caesar_decrypt 函数：接收密文字符串和密钥 k，遍历每个字

符，对大写字母执行移位解密计算，非字母字符直接保留。
• 穷举循环：遍历 k=1~25，调用解密函数并输出所有结果，符合实验要求的格式。

六、实验结果与分析

1. 程序运行输出（完整结果）
穷举破解凯撒密码结果：
k=1  : MTEDBLVAXTILAHPFXMAXVHWX
k=2  : LSDCAKUZWSHKZGOEWLZWUGVW
k=3  : KRCBZJTYVRGJYFNDVKYVTFUV
k=4  : JQBAYISXUQFIXEMCUJXUSETU
k=5  : IPAZXHRWTPEHWDLBTIWTRDST
k=6  : HOZYWGQVSODGVCKASHVSQCRS
k=7  : GNYXVFPURNCFUBJZRGURPBQR
k=8  : FMXWUEOTQMBETAIYQFTQOAPQ
k=9  : ELWVTDNSPLADSZHXPESPNZOP
k=10 : DKVUSCMROKZCRYGWODROMYNO
k=11 : CJUTRBLQNJYBQXFVNCQNLXMN
k=12 : BITSQAKPMIXAPWEUMBPMKWLM
k=13 : AHSRPZJOLHWZOVDTLAOLJVKL
k=14 : ZGRQOYINKGVYNUCSKZNKIUJK
k=15 : YFQPNXHMJFUXMTBRJYMJHTIJ
k=16 : XEPOMWGLIETWLSAQIXLIGSHI
k=17 : WDONLVFKHDSVKRZPHWKHFRGH
k=18 : VCNMKUEJGCRUJQYOGVJGEQFG
k=19 : UBMLJTDIFBQTIPXNFUIFDPEF
k=20 : TALKISCHEAPSHOWMETHECODE
k=21 : SZKJHRBGDZORGNVLDSGDBNCD
k=22 : RYJIGQAFCYNQFMUKCRFCAMBC
k=23 : QXIHFPZEBXMPELTJBQEBZLAB
k=24 : PWHGEOYDAWLODKSIAPDAYKZA
k=25 : OVGFDNXCZVKNCJRHZOCZXJYZ
2. 结果分析

遍历所有密钥后，仅当 k=20 时，解密结果 LSDCAKZUWSHZAGNWDLZWUGVW 符合英文文本的结构特征（字母组合自然，无无意义乱序），其余密钥对应的解密结果均为无意义字符序列。

因此可确定：

• 正确密钥：k=20

• 对应明文：TALKISCHEAPSHOWMETHECODE

七、实验结论

1. 成功实现了基于穷举法的凯撒密码破解，完全符合实验要求。

2. 验证了凯撒密码密钥空间过小的安全缺陷，极易被暴力破解。

3. 掌握了 Python 实现凯撒密码解密的核心逻辑，为后续学习更复杂的密码算法奠定了基础。

八、实验思考与拓展

1. 安全性问题：凯撒密码在实际应用中几乎无安全性，需采用 Vigenère 密码、AES 等更安全的算法。

2. 自动化筛选：可引入英文词典或字母频率分析，实现自动识别有意义明文，无需人工筛选。

3. 兼容性优化：可扩展代码支持小写字母、数字及特殊字符的解密处理。

