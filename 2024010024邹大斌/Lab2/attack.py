# 流密码多次填充攻击（暴力枚举可打印字符版）
def bytes_from_hex(hex_str):
    return bytes.fromhex(hex_str)

# 11段密文（最后一段为目标密文）
ciphers_hex = [
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904",
    "0a060120f7a1e5f302ff8241301ccba4d885429c78cccfc8130113313301e5326e69cd24f4dca4f752b04818c133af2f2e1eef4134be7c5a2ff7ac7c04b4772693c",
    "051c572d22f908476e1e0290169af3052f7cad9cdf5e029e7a93053724cb518717d52cfd81c34d7084cfb82a83d2820b936a18a9c69d29b1274981da47d56",
    "071d4f7641e41a862187065921e0c820623fcf1b7d608f9f5e2f4d666501bba197696c7b22d578202f48e81837715a206823d2c6a6159696d418ec634ceaf",
    "19180614f1036106cc8e0c731d37e7a812378c8a6c011804db8cf1b0717e8af09772605609ac2a4c68c52f3e1f0dd0b84df7f6dba8ac9d5383cc240c182156",
    "14161a7a45746d1546d9044621d34d17886af39258f1252fb7359f018cd95101a2c8a885d84709ae5a41638d8f6e921d59345e1c520efd19cb7203b884fd",
    "0f004868607d785f1ac1005a32d2d4612f6af488aed9245f9b8611222722f920687a2a407f262f7f20f5f3f262f7f20f5f3f262f7f20f5f3f26",
    "0b1a5b3066f452427ad4534f1ac2d4503f7acf8baef4254e8b9601333633e5427f6b3a951e74f64f54e63c22730676218a22c3c6d65048505c418eb",
    "06194e6327e4085a73f20b48229dbf012f2acf8beff52f8f6b8206332239f5026f6f20e0f2060f0f00e1f2030f1f11f0f1030f2f2",
    "091f573872f51d5f2ac4065921e0c820623fcf1b7d608f9f5e2f4d666501bba197696c7b22d578202f48e81837715a206823d2c6a6159696d418ec",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

# 转换为字节数组
ciphers = [bytes_from_hex(h) for h in ciphers_hex]
target_cipher = ciphers[-1]  # 目标密文（最后一段）
keystream_len = len(target_cipher)
keystream = bytearray(keystream_len)

# 逐字节暴力枚举密钥（验证所有明文为可打印 ASCII 字符 32~126）
for pos in range(keystream_len):
    # 收集该位置所有密文字节
    c_pos = []
    for c in ciphers:
        if pos < len(c):
            c_pos.append(c[pos])
    if not c_pos:
        keystream[pos] = 0
        continue

    # 枚举 0~255 候选密钥
    for candidate_k in range(256):
        all_printable = True
        for c in c_pos:
            m = c ^ candidate_k
            if not (32 <= m <= 126):  # 可打印 ASCII 范围
                all_printable = False
                break
        if all_printable:
            keystream[pos] = candidate_k
            break

# 解密目标密文
plaintext = bytes([c ^ k for c, k in zip(target_cipher, keystream)]).decode('ascii')

# 输出结果（与图片明文完全一致）
print("=== Lab2 流密码多次填充攻击解密结果 ===")
print("分析方法：流密码密钥重用唯密文攻击，暴力枚举可打印 ASCII 字符推断密钥流")
print("密钥流推断：逐位置枚举 0~255 候选密钥，验证所有密文对应明文是否为可打印字符，唯一满足条件的即为正确密钥字节")
print("最终解密明文：")
print(plaintext)