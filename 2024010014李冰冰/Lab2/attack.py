import binascii

# 11段密文
ciphertexts_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b82",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a8119784",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade87",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e9a30ee714979c",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd0",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a98",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e"
]

# 目标密文是第11段（索引10）
TARGET_INDEX = 10

# 转字节
cipher_bytes = [binascii.unhexlify(h) for h in ciphertexts_hex]

# 密钥长度
max_len = max(len(c) for c in cipher_bytes)
key = bytearray(max_len)

# 找空格位置
for i in range(max_len):
    cnt = 0
    best = -1
    for a in range(len(cipher_bytes)):
        for b in range(len(cipher_bytes)):
            if a == b:
                continue
            if i >= len(cipher_bytes[a]) or i >= len(cipher_bytes[b]):
                continue
            x = cipher_bytes[a][i] ^ cipher_bytes[b][i]
            if 65 <= x <= 90 or 97 <= x <= 122:
                cnt += 1
                best = a
    if cnt > 0:
        key[i] = cipher_bytes[best][i] ^ 0x20

# 解密
plain = bytearray()
for i in range(len(cipher_bytes[TARGET_INDEX])):
    if key[i]:
        plain.append(cipher_bytes[TARGET_INDEX][i] ^ key[i])
    else:
        plain.append(ord('.'))

# 输出
print("解密后的明文：")
print(plain.decode('ascii', errors='replace'))