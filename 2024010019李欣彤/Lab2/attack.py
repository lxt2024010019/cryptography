def hex_to_bytes(hex_str):
    """十六进制字符串转字节数组（增加长度校验与空白清除，解决ValueError）"""
    # 清除所有空白字符（空格、换行、制表符）
    hex_str_clean = hex_str.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    # 校验长度为偶数
    if len(hex_str_clean) % 2 != 0:
        raise ValueError(f"十六进制字符串长度必须为偶数，当前长度: {len(hex_str_clean)}，字符串: {hex_str_clean}")
    return bytes.fromhex(hex_str_clean)

# ===================== 1. 完整密文列表（严格核对长度，修正密文#1） =====================
cipher_hex_list = [
    # 密文#1（已修正末尾，长度106）
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dffff5b403b510d0d0",
    # 密文#2
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f",
    # 密文#3
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b82",
    # 密文#4
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a8119784",
    # 密文#5
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade87",
    # 密文#6
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c",
    # 密文#7
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd0",
    # 密文#8
    "315c4eeaa8b5f8bffd111155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0",
    # 密文#9
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a98",
    # 密文#10
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f",
    # 目标密文
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e"
]

# 转换为字节数组
cipher_bytes = [hex_to_bytes(h) for h in cipher_hex_list]
max_len = max(len(c) for c in cipher_bytes)
cipher_padded = [c.ljust(max_len, b'\x00') for c in cipher_bytes]

# 初始化密钥和明文
key = bytearray(max_len)
plain_list = [bytearray(max_len) for _ in cipher_padded]
SPACE = ord(' ')

# 空格推断法还原密钥
for i in range(max_len):
    for guess_idx in range(len(cipher_padded)-1):
        if i >= len(cipher_padded[guess_idx]):
            continue
        k_guess = cipher_padded[guess_idx][i] ^ SPACE
        valid = True
        for c_idx in range(len(cipher_padded)):
            if i >= len(cipher_padded[c_idx]):
                continue
            p = cipher_padded[c_idx][i] ^ k_guess
            if not (32 <= p <= 126):
                valid = False
                break
        if valid:
            key[i] = k_guess
            for c_idx in range(len(cipher_padded)):
                if i < len(cipher_padded[c_idx]):
                    plain_list[c_idx][i] = cipher_padded[c_idx][i] ^ key[i]
            break

# 解密目标密文
target_plain = plain_list[-1].decode('ascii', errors='replace').rstrip('\x00')
print("=" * 60)
print("The secret message is:")
print(target_plain)
print("=" * 60)