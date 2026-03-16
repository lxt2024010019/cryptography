cipher_text = "NUFECMWBYUJMBIQGYNBYWIXY"

# 遍历所有可能的密钥 k (1~25)
for k in range(1, 26):
    plain_text = []
    for c in cipher_text:
        if c.isupper():
            # 计算解密后的字符序号：(原序号 - k) 模 26
            char_index = (ord(c) - ord('A') - k) % 26
            plain_text.append(chr(char_index + ord('A')))
        else:
            plain_text.append(c)  # 非字母字符保持不变
    # 输出当前密钥对应的解密结果
    print(f"k={k} : {''.join(plain_text)}")