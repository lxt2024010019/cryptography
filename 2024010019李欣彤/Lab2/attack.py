
import itertools


ciphertexts_hex = [
    ### 密文 #1

"315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e"


### 密文 #2

"234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f"


### 密文 #3

"32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb"


### 密文 #4

"32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa"


### 密文 #5

"3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070"


### 密文 #6

"32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4"


### 密文 #7

"32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce"


### 密文 #8

"315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3"


### 密文 #9

"271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027"


### 密文 #10

"466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
]


# 目标密文（完整）
target_hex = "32510ba9babebb6fed001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"


def safe_fromhex(hex_str):
    hex_str = hex_str.strip()
    if len(hex_str) % 2 != 0:
        print(f"警告：十六进制字符串长度为奇数({len(hex_str)})，自动在末尾补 '0'")
        hex_str += '0'
    return bytes.fromhex(hex_str)

# 转换所有密文
ciphertexts = [safe_fromhex(hex_str) for hex_str in ciphertexts_hex]
target = safe_fromhex(target_hex)

# 确定所有密文的最大长度
max_len = max(len(c) for c in ciphertexts + [target])

# 填充到相同长度（不足补0）
padded_ciphers = [c + b'\x00' * (max_len - len(c)) for c in ciphertexts]
padded_target = target + b'\x00' * (max_len - len(target))

# 初始化密钥流
key_stream = [None] * max_len

# 定义字符集
space = ord(' ')
letters = set(range(65, 91)) | set(range(97, 123))  # A-Z a-z


possible_keys = [set() for _ in range(max_len)]

for i, j in itertools.combinations(range(len(padded_ciphers)), 2):
    c1 = padded_ciphers[i]
    c2 = padded_ciphers[j]
    for pos in range(max_len):
        xor_val = c1[pos] ^ c2[pos]
        if xor_val in letters:
            # 假设 M1 是空格
            m1_guess = space
            m2_guess = space ^ xor_val
            if m2_guess in letters:
                key_guess = c1[pos] ^ m1_guess
                possible_keys[pos].add(key_guess)
            # 假设 M2 是空格
            m2_guess = space
            m1_guess = space ^ xor_val
            if m1_guess in letters:
                key_guess = c2[pos] ^ m2_guess
                possible_keys[pos].add(key_guess)

# 从候选集中确定唯一密钥
for pos in range(max_len):
    if len(possible_keys[pos]) == 1:
        key_stream[pos] = possible_keys[pos].pop()

changed = True
while changed:
    changed = False
    for pos in range(max_len):
        if key_stream[pos] is not None:
            key = key_stream[pos]
            for idx, c in enumerate(padded_ciphers):
                plain = c[pos] ^ key
                if plain == space:
                    for other_pos in range(max_len):
                        if other_pos != pos and key_stream[other_pos] is None:
                            key_guess = padded_ciphers[idx][other_pos] ^ space
                            other_plain = padded_ciphers[idx][other_pos] ^ key_guess
                            if other_plain in letters:
                                possible_keys[other_pos].add(key_guess)
                                if len(possible_keys[other_pos]) == 1:
                                    key_stream[other_pos] = possible_keys[other_pos].pop()
                                    changed = True
    for pos in range(max_len):
        if key_stream[pos] is None and len(possible_keys[pos]) == 1:
            key_stream[pos] = possible_keys[pos].pop()
            changed = True


for pos in range(max_len):
    if key_stream[pos] is None:
        if possible_keys[pos]:
            key_stream[pos] = next(iter(possible_keys[pos]))
        else:
            key_stream[pos] = 0  # 理论上不会发生

key_bytes = bytes(key_stream)


decrypted = bytes([padded_target[i] ^ key_bytes[i] for i in range(len(padded_target))])
decrypted = decrypted[:len(target)]

print("解密结果：")
try:
    print(decrypted.decode('ascii'))
except UnicodeDecodeError:
    print(decrypted.decode('ascii', errors='replace'))

def hex_to_bytes(hex_str):
    """十六进制字符串转字节数组（增加长度校验与空白清除，解决ValueError）"""
    # 清除所有空白字符（空格、换行、制表符）
    hex_str_clean = hex_str.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    # 校验长度为偶数
    if len(hex_str_clean) % 2 != 0:
        raise ValueError(f"十六进制字符串长度必须为偶数，当前长度: {len(hex_str_clean)}，字符串: {hex_str_clean}")
    return bytes.fromhex(hex_str_clean)


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
