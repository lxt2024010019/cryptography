ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

# 穷举1到25的密钥
for k in range(1, 26):
    plaintext = ""
    # 遍历密文中的每个字符
    for char in ciphertext:
        # 仅处理大写字母
        if char.isupper():
            # 计算解密后的字母（向前移k位）
            shifted = ord(char) - k
            # 如果字母超出A，就循环到Z
            if shifted < ord('A'):
                shifted += 26
            # 把数字变回字母
            plaintext += chr(shifted)
        else:
            # 非字母字符直接保留
            plaintext += char
    # 输出每个密钥对应的解密结果（格式化输出，占两位）
    print(f"k={k:2d} : {plaintext}")