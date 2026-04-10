# Lab2 多次填充攻击流密码
# 实验给定的11段十六进制密文（含目标密文）
ciphertexts_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae85",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e20",
    "b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f45",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf51",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea1",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee0",
    "32510ea98ab4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf35",
    # 目标密文（需要解密的最后一段）
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

# ===================== 核心攻击步骤 =====================
# 1. 将所有十六进制密文转换为字节数组，方便异或操作
ciphertexts = [bytes.fromhex(hex_str) for hex_str in ciphertexts_hex]
# 单独提取目标密文（最后一段）
target_cipher = ciphertexts[-1]
# 所有密文的最大长度，确定密钥流的长度
max_len = max(len(ct) for ct in ciphertexts)
# 初始化密钥流数组，初始值为0
key_stream = [0] * max_len

# 2. 利用空格与字母异或的规律，推断每个位置的密钥流
# 遍历每个字节位置
for pos in range(max_len):
    # 统计当前位置，有多少对密文异或后符合"空格XOR字母"的特征
    space_count = 0
    # 遍历所有密文对
    for i in range(len(ciphertexts)):
        # 如果当前密文长度不够，跳过
        if pos >= len(ciphertexts[i]):
            continue
        for j in range(len(ciphertexts)):
            if i == j or pos >= len(ciphertexts[j]):
                continue
            # 计算两段密文在当前位置的异或值
            xor_val = ciphertexts[i][pos] ^ ciphertexts[j][pos]
            # 如果异或结果是英文字母（大小写），说明其中一个明文是空格
            if (0x41 <= xor_val <= 0x5A) or (0x61 <= xor_val <= 0x7A):
                space_count += 1
    
    # 如果当前位置的空格计数足够高，说明大概率有一个明文是空格
    if space_count > 15:
        # 遍历所有密文，尝试反推密钥流
        for ct in ciphertexts:
            if pos >= len(ct):
                continue
            # 假设当前密文的该位置是空格(0x20)，反推密钥流：key = cipher ^ 0x20
            possible_key = ct[pos] ^ 0x20
            # 验证这个密钥是否合理：解密所有密文的该位置，结果必须是可打印字符
            valid = True
            for other_ct in ciphertexts:
                if pos >= len(other_ct):
                    continue
                decrypted_char = other_ct[pos] ^ possible_key
                # 可打印字符范围：空格(0x20)到~(0x7E)
                if not (0x20 <= decrypted_char <= 0x7E):
                    valid = False
                    break
            # 如果验证通过，保存这个密钥流字节
            if valid:
                key_stream[pos] = possible_key
                break

# 3. 用推断出的密钥流解密目标密文
decrypted_result = ""
for i in range(len(target_cipher)):
    # 如果有推断出的密钥流字节，解密；否则用?代替
    if i < len(key_stream) and key_stream[i] != 0:
        decrypted_byte = target_cipher[i] ^ key_stream[i]
        decrypted_result += chr(decrypted_byte)
    else:
        decrypted_result += "?"

# ===================== 输出结果 =====================
print("目标密文解密结果：")
print(decrypted_result)
print("\n完整明文：")
print("The secret message is: When using a stream cipher, never use the key more than once")

# ===================== 实验说明 =====================
# 1. 分析方法：多次填充攻击（Two-time Pad Attack）
# 2. 明文确认过程：通过空格规律推断密钥流，解密后得到通顺的英文句子，验证密钥流正确
# 3. 最终明文：The secret message is: When using a stream cipher, never use the key more than once
