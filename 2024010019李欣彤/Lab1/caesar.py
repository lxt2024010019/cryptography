# Lab1：穷举法破译凯撒密码
# 功能：对密文进行所有1~25位的凯撒解密，并输出

cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

for k in range(1, 26):
    plain = ""
    for c in cipher:
        if 'A' <= c <= 'Z':
            # 解密：往前移k位，循环26个字母
            num = ord(c) - ord('A')
            num = (num - k) % 26
            plain += chr(num + ord('A'))
        else:
            plain += c
    print(f"k={k:<2d} : {plain}")