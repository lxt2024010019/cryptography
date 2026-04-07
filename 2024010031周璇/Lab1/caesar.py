# Lab1 穷举法破解凯撒密码
# 实验给定的密文
cipher_text = "NUFECMWBYUJMBIQGYNBYWIXY"

# 遍历1~25所有可能的密钥
for k in range(1, 26):
    plain_result = ""
    # 逐个字符解密
    for char in cipher_text:
        # 仅处理大写英文字母，匹配实验输入
        if char.isupper():
            # 字母转0-25的序号，方便计算
            char_num = ord(char) - ord('A')
            # 凯撒解密核心：往前移k位，模26处理字母循环
            new_num = (char_num - k) % 26
            # 转回大写字母
            new_char = chr(new_num + ord('A'))
            plain_result += new_char
        else:
            plain_result += char
    # 严格按照实验要求的格式输出
    print(f"k={k:<2} : {plain_result}")

# ===================== 实验结果说明 =====================
# 1. 正确的密钥k：20
# 2. 解密后的明文：TALKISCHEAPSHOWMETHECODE（完整语义：TALK IS CHEAP SHOW ME THE CODE）
# 3. 明文判断依据：
#    凯撒密码密钥范围仅1~25，遍历所有密钥后，仅k=20的解密结果是有完整语义的英文句子，
#    其余密钥的结果均为无意义乱码，因此确定该结果为正确明文，k=20为正确密钥。
