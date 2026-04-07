# Lab1: 穷举法破译凯撒密码
# 学号：请填写你的学号
# 姓名：请填写你的姓名

# 给定的密文
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

print("正在使用穷举法尝试所有可能的密钥 (1~25)...\n")

# 遍历所有可能的密钥 k (1 到 25)
for k in range(1, 26):
    plaintext = []
    for char in ciphertext:
        # 只处理大写字母
        if 'A' <= char <= 'Z':
            # 核心解密算法：
            # 1. 将字母转换为 0-25 的数字 (ord(char) - ord('A'))
            # 2. 减去密钥 k 进行反向移位
            # 3. 使用 % 26 处理循环越界（例如从 A 回到 Z）
            # 4. 转换回字符
            shifted_code = (ord(char) - ord('A') - k) % 26
            plaintext_char = chr(shifted_code + ord('A'))
            plaintext.append(plaintext_char)
        else:
            # 如果有非字母字符，保持不变
            plaintext.append(char)
    
    # 拼接结果并按要求格式输出
    result = ''.join(plaintext)
    print(f"k={k:<2} : {result}")

print("\n--- 解密完成 ---")
# 提示：正确的明文是人类可读的英文句子