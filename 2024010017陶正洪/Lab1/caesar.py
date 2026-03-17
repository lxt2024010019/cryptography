# Lab1: 穷举法破译凯撒密码
# 实验给定的待解密密文
cipher_text = "NUFECMWBYUJMBIQGYNBYWIXY"

print("凯撒密码穷举解密结果：")
print("=" * 50)

# 穷举所有可能的密钥k（1~25），符合实验要求
for k in range(1, 26):
    plain_text = ""
    # 遍历密文的每个字符进行解密
    for c in cipher_text:
        # 仅处理大写英文字母（本题密文均为大写）
        if c.isupper():
            # 将字母转换为0-25的字母表位置（A对应0，Z对应25）
            char_num = ord(c) - ord('A')
            # 核心解密逻辑：前移k位，模26实现字母循环（自动处理负数）
            decrypt_num = (char_num - k) % 26
            # 转换回大写字母
            decrypt_char = chr(decrypt_num + ord('A'))
            plain_text += decrypt_char
        else:
            # 非字母字符直接保留（本题无此类字符）
            plain_text += c
    # 严格按照实验要求的格式输出
    print(f"k={k:<2d} : {plain_text}")

# 实验结果说明（符合报告要求）
print("\n" + "=" * 50)
print("实验结果说明：")
print("1. 正确的密钥k：20")
print("2. 解密后的明文：TALKISCHEAPSHOWMETHECODE")
print("3. 判断依据：")
print("   凯撒密码的密钥范围仅1~25，穷举所有结果后，只有k=20对应的解密结果是有意义的英文句子，")
print("   对应经典技术名言 \"Talk is cheap, show me the code\"，符合明文的语义要求，因此为正确结果。")
