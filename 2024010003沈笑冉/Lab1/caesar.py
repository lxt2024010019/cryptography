# 凯撒密码解密函数
def caesar_decrypt(ciphertext, k):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # 处理大写字母
            if char.isupper():
                original = ord(char) - ord('A')
                # 向前移动k位，模26保证字母循环
                shifted = (original - k) % 26
                plaintext += chr(shifted + ord('A'))
            # 兼容小写字母
            else:
                original = ord(char) - ord('a')
                shifted = (original - k) % 26
                plaintext += chr(shifted + ord('a'))
        else:
            # 非字母字符不做处理
            plaintext += char
    return plaintext

# 待破解的密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

# 穷举所有密钥1~25
print("========== 穷举法破解凯撒密码结果 ==========")
for k in range(1, 26):
    result = caesar_decrypt(ciphertext, k)
    print(f"密钥 k={k:2d}：{result}")

# 正确密钥与明文输出
correct_key = 20
final_plaintext = caesar_decrypt(ciphertext, correct_key)
print("\n========== 破解成功 ==========")
print(f"正确密钥：k = {correct_key}")
print(f"解密明文：{final_plaintext}")