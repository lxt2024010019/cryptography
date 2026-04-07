# Lab1 穷举法破解凯撒密码
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

# 遍历所有可能的密钥 k（1~25）
for k in range(1, 26):
    plaintext = ""
    for char in ciphertext:
        if char.isupper():
            # 解密：将大写字母向前移 k 位，超出范围则循环
            shifted = ord(char) - k
            if shifted < ord('A'):
                shifted += 26
            plaintext += chr(shifted)
        else:
            plaintext += char
    print(f"k={k}: {plaintext}")