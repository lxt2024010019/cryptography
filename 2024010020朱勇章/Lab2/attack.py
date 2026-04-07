import binascii

# --- 1. 定义密文数据 ---
# 注意：此处的数据是根据图片中的十六进制字符串提取的。
# 如果你的图片中有更多的密文样本，请添加到列表中以提高成功率。
ciphertexts_hex = [
    "315c4eeab655b5b0f81c4b5e7c87ee0919b15167374f021f405e8149b88347a334b8f500a062fcaaaeb3a9382060b1b24b366861a39f16d4ec4b5bb36b5f8751b054c92821c6bd4422f63db6f9b76b7fc820ff8667b23220927",
    "231460b6c9f331c1ea88b4e532215b0f17c6a9151652b853b7071acc59a790881ffe7d518f8f4b2526ed676e4b861a4156db8517a5208571a7ee4a7",
    "271946d3c9485584b225b39ca62c2c04d513c6a50af62a0b27e36433080262195f428fe5b57c6cc4112644ce2a765cd84caf3560b4ff69cc25851e764e2273f320b1b5514aa2333ead7bc1dd542e9724d92f8f8d5a577e2365383ce712ee4bc414e94c7e25032c734471",
    "32551db43c2856908885c3951b6ad480840b3215d10a6292691212822d1c48bf6a5aca4bc3e3e24ae46fa8f35a6c71beff6551d28bd8f881a19510f4ebf83f797a1c3995c10d2800e00b86dd789a7c25b53490112",
    "466d0be4ce998b7a2f51d464fed2ced7641ddaa3cc31c9941cf10ab0f409ed39590005b3399ccfa061d03155ca8a3140e138a9f32583b6dac8067f03ad5f3575c3b8edc9ba7537530541a00f93c004ff50d66f1d559ba520e09a2cb20b3",
    "315c4eeab655b5b0f81c4b5e7c87ee0919b15167374f021f405e8149b88347a334b8f500a062fcaaaeb3a9382060b1b24b366861a39f16d4ec4b5bb36b5f8751b054c92821c6bd4422f63db6f9b76b7fc820ff8667b23220927",
    "271946d3c9485584b225b39ca62c2c04d513c6a50af62a0b27e36433080262195f428fe5b57c6cc4112644ce2a765cd84caf3560b4ff69cc25851e764e2273f320b1b5514aa2333ead7bc1dd542e9724d92f8f8d5a577e2365383ce712ee4bc414e94c7e25032c734471",
    "32551db43c2856908885c3951b6ad480840b3215d10a6292691212822d1c48bf6a5aca4bc3e3e24ae46fa8f35a6c71beff6551d28bd8f881a19510f4ebf83f797a1c3995c10d2800e00b86dd789a7c25b53490112",
    "466d0be4ce998b7a2f51d464fed2ced7641ddaa3cc31c9941cf10ab0f409ed39590005b3399ccfa061d03155ca8a3140e138a9f32583b6dac8067f03ad5f3575c3b8edc9ba7537530541a00f93c004ff50d66f1d559ba520e09a2cb20b3",
    "315c4eeab655b5b0f81c4b5e7c87ee0919b15167374f021f405e8149b88347a334b8f500a062fcaaaeb3a9382060b1b24b366861a39f16d4ec4b5bb36b5f8751b054c92821c6bd4422f63db6f9b76b7fc820ff8667b23220927",
    "271946d3c9485584b225b39ca62c2c04d513c6a50af62a0b27e36433080262195f428fe5b57c6cc4112644ce2a765cd84caf3560b4ff69cc25851e764e2273f320b1b5514aa2333ead7bc1dd542e9724d92f8f8d5a577e2365383ce712ee4bc414e94c7e25032c734471",
    "32551db43c2856908885c3951b6ad480840b3215d10a6292691212822d1c48bf6a5aca4bc3e3e24ae46fa8f35a6c71beff6551d28bd8f881a19510f4ebf83f797a1c3995c10d2800e00b86dd789a7c25b53490112",
    "466d0be4ce998b7a2f51d464fed2ced7641ddaa3cc31c9941cf10ab0f409ed39590005b3399ccfa061d03155ca8a3140e138a9f32583b6dac8067f03ad5f3575c3b8edc9ba7537530541a00f93c004ff50d66f1d559ba520e09a2cb20b3",
    "315c4eeab655b5b0f81c4b5e7c87ee0919b15167374f021f405e8149b88347a334b8f500a062fcaaaeb3a9382060b1b24b366861a39f16d4ec4b5bb36b5f8751b054c92821c6bd4422f63db6f9b76b7fc820ff8667b23220927",
    "271946d3c9485584b225b39ca62c2c04d513c6a50af62a0b27e36433080262195f428fe5b57c6cc4112644ce2a765cd84caf3560b4ff69cc25851e764e2273f320b1b5514aa2333ead7bc1dd542e9724d92f8f8d5a577e2365383ce712ee4bc414e94c7e25032c734471",
    "32551db43c2856908885c3951b6ad480840b3215d10a6292691212822d1c48bf6a5aca4bc3e3e24ae46fa8f35a6c71beff6551d28bd8f881a19510f4ebf83f797a1c3995c10d2800e00b86dd789a7c25b53490112",
    "466d0be4ce998b7a2f51d464fed2ced7641ddaa3cc31c9941cf10ab0f409ed39590005b3399ccfa061d03155ca8a3140e138a9f32583b6dac8067f03ad5f3575c3b8edc9ba7537530541a00f93c004ff50d66f1d559ba520e09a2cb20b3",
    "315c4eeab655b5b0f81c4b5e7c87ee0919b15167374f021f405e8149b88347a334b8f500a062fcaaaeb3a9382060b1b24b366861a39f16d4ec4b5bb36b5f8751b054c92821c6bd4422f63db6f9b76b7fc820ff8667b23220927",
    "271946d3c9485584b225b39ca62c2c04d513c6a50af62a0b27e36433080262195f428fe5b57c6cc4112644ce2a765cd84caf3560b4ff69cc25851e764e2273f320b1b5514aa2333ead7bc1dd542e9724d92f8f8d5a577e2365383ce712ee4bc414e94c7e25032c734471",
    "32551db43c2856908885c3951b6ad480840b3215d10a6292691212822d1c48bf6a5aca4bc3e3e24ae46fa8f35a6c71beff6551d28bd8f881a19510f4ebf83f797a1c3995c10d2800e00b86dd789a7c25b53490112",
    "466d0be4ce998b7a2f51d464fed2ced7641ddaa3cc31c9941cf10ab0f409ed39590005b3399ccfa061d03155ca8a3140e138a9f32583b6dac8067f03ad5f3575c3b8edc9ba7537530541a00f93c004ff50d66f1d559ba520e09a2cb20b3"
]

def hex_xor(a, b):
    """对两个十六进制字符串进行异或运算，返回字节对象"""
    return bytes([x ^ y for x, y in zip(binascii.unhexlify(a), binascii.unhexlify(b))])

def guess_space(c1_bytes, c2_bytes, key_bytes, pos):
    """
    尝试猜测某个位置是否为空格。
    如果C1[pos] ^ C2[pos]是可打印字符，且符合大小写特征，则可能有一方是空格。
    """
    xor_result = c1_bytes[pos] ^ c2_bytes[pos]
    # 检查是否为可打印字符，且符合字母/空格异或后的特征
    if 0x20 <= xor_result <= 0x7E:
        # 如果结果是大写字母，说明其中一个可能是小写字母，另一个是空格
        # 如果结果是小写字母，说明其中一个可能是大写字母，另一个是空格
        # 如果结果是0x00，说明两者相同
        if chr(xor_result).isalpha() or xor_result == 0x20:
            # 猜测C1是空格，推导出密钥
            key_guess = c1_bytes[pos] ^ 0x20
            key_bytes[pos] = key_guess
            # 使用此密钥解密所有密文的该位置
            for i in range(len(ciphertexts_hex)):
                c_bytes = binascii.unhexlify(ciphertexts_hex[i])
                if pos < len(c_bytes):
                    plaintext_bytes[i][pos] = c_bytes[pos] ^ key_guess

# --- 2. 攻击流程 ---
# 将十六进制密文转换为字节对象列表
ciphertexts_bytes = [binascii.unhexlify(c) for c in ciphertexts_hex]

# 初始化明文存储列表，用0填充
plaintext_bytes = [[0] * max(len(c) for c in ciphertexts_bytes) for _ in range(len(ciphertexts_hex))]

# 初始化密钥存储
key_bytes = [0] * max(len(c) for c in ciphertexts_bytes)

# --- 3. 核心攻击逻辑 ---
# 遍历所有密文对
for i in range(len(ciphertexts_bytes)):
    for j in range(i + 1, len(ciphertexts_bytes)):
        c1 = ciphertexts_bytes[i]
        c2 = ciphertexts_bytes[j]
        min_len = min(len(c1), len(c2))

        # 遍历每个字节位置
        for pos in range(min_len):
            # 计算两密文的异或值
            xor_byte = c1[pos] ^ c2[pos]

            # 判断逻辑：如果异或结果是可打印字符，且可能是空格造成的
            # 这里简化为：如果异或结果看起来像字母（或符号），则尝试推导
            if 0x20 <= xor_byte <= 0x7E:
                # 这里实现简单的推导逻辑
                # 如果 C1 ^ C2 的结果是大写字母，说明 C1 可能是小写，C2 可能是空格，反之亦然
                # 我们尝试假设 C1 的该位置是空格
                if chr(xor_byte).isupper():
                    # C1[pos] ^ C2[pos] = 大写字母 -> C1可能是小写字母，C2可能是空格
                    # 或者 C1是空格，C2是小写字母
                    # 尝试假设 C2 是空格
                    key_bytes[pos] = c2[pos] ^ 0x20
                    # 尝试假设 C1 是空格
                    # key_bytes[pos] = c1[pos] ^ 0x20
                elif chr(xor_byte).islower():
                    # C1[pos] ^ C2[pos] = 小写字母 -> C1可能是大写字母，C2可能是空格
                    key_bytes[pos] = c2[pos] ^ 0x20
                # 如果是其他符号，也可以尝试推导，但准确率较低

# --- 4. 生成最终明文 ---
print("### 解密结果 ###")
for idx, c_bytes in enumerate(ciphertexts_bytes):
    plaintext = ""
    for pos in range(len(c_bytes)):
        if key_bytes[pos] != 0:  # 如果该位置的密钥已知
            char = c_bytes[pos] ^ key_bytes[pos]
            if 0x20 <= char <= 0x7E:
                plaintext += chr(char)
            else:
                plaintext += "."  # 不可打印字符用点代替
        else:
            plaintext += "?"  # 密钥未知用问号代替
    print(f"明文 {idx+1}: {plaintext}")

# 注意：实际实验中，你需要根据输出的乱码，手动调整猜测逻辑，
# 或者编写更复杂的词频分析脚本来自动填充。
# 这里为了演示原理，代码较为简化。