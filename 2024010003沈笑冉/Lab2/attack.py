import binascii

# 所有密文字符串（包含10个已知密文+1个目标密文）
ciphertexts_hex = [
    # 密文1
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    # 密文2
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    # 密文3
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    # 密文4
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    # 密文5
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    # 密文6
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    # 密文7
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    # 密文8
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    # 密文9
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    # 密文10
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    # 目标密文
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

# 将十六进制密文转换为字节数组
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# 将字节数组转换为十六进制字符串
def bytes_to_hex(byte_arr):
    return binascii.hexlify(byte_arr).decode('utf-8')

# 对两个字节数组进行异或操作
def xor_bytes(a, b):
    # 确保两个字节数组长度相同（取较短长度）
    min_len = min(len(a), len(b))
    return bytes([a[i] ^ b[i] for i in range(min_len)])

# 从明文异或结果中推断空格位置，并还原密钥流
def infer_key_and_plaintext(ciphertexts):
    # 转换所有密文为字节数组
    c_bytes = [hex_to_bytes(ct) for ct in ciphertexts]
    num_ct = len(c_bytes)
    max_len = max(len(ct) for ct in c_bytes)
    
    # 初始化密钥流（初始为0）
    key_stream = [0] * max_len
    # 存储推断出的明文
    plaintexts = [bytearray([0]*len(ct)) for ct in c_bytes]
    
    # 核心逻辑：利用空格与字母的异或特性推断空格位置，进而还原密钥
    for pos in range(max_len):
        # 统计每个密文在该位置是否可能是空格（通过异或结果判断）
        space_candidates = []
        for i in range(num_ct):
            if pos >= len(c_bytes[i]):
                continue
            # 遍历其他密文，对比异或结果是否符合 字母^空格 的特征
            for j in range(i+1, num_ct):
                if pos >= len(c_bytes[j]):
                    continue
                xor_val = c_bytes[i][pos] ^ c_bytes[j][pos]
                # 检查是否符合 字母^空格 (大小写翻转) 或 空格^空格(0) 或 字母^字母
                if (xor_val >= 0x20 and xor_val <= 0x7E) or xor_val == 0:
                    # 若异或结果是大小写字母差（0x20），则其中一个大概率是空格
                    if xor_val == 0x20:
                        space_candidates.append((i, pos))
                        space_candidates.append((j, pos))
                    # 若异或结果为0，两个位置都是空格
                    elif xor_val == 0:
                        space_candidates.append((i, pos))
                        space_candidates.append((j, pos))
        
        # 基于候选空格位置推断密钥
        for (ct_idx, p) in space_candidates:
            if p >= len(c_bytes[ct_idx]):
                continue
            # 假设该位置是空格（0x20），计算密钥流
            key_candidate = c_bytes[ct_idx][p] ^ 0x20
            # 验证该密钥是否在其他位置合理
            valid = True
            for i in range(num_ct):
                if p >= len(c_bytes[i]):
                    continue
                plain_char = c_bytes[i][p] ^ key_candidate
                # 验证明文是否为可打印字符（空格/字母/数字/符号）
                if not (0x20 <= plain_char <= 0x7E):
                    valid = False
                    break
            if valid:
                key_stream[p] = key_candidate
                # 还原该位置所有明文
                for i in range(num_ct):
                    if p < len(c_bytes[i]):
                        plaintexts[i][p] = c_bytes[i][p] ^ key_candidate
    
    # 补全未推断出的密钥（若有），默认填充0（可手动调整）
    for pos in range(max_len):
        if key_stream[pos] == 0:
            # 取该位置最可能的密钥（基于可打印字符）
            possible_keys = []
            for k in range(0x00, 0xFF):
                valid = True
                for i in range(num_ct):
                    if pos >= len(c_bytes[i]):
                        continue
                    pc = c_bytes[i][pos] ^ k
                    if not (0x20 <= pc <= 0x7E):
                        valid = False
                        break
                if valid:
                    possible_keys.append(k)
            if possible_keys:
                key_stream[pos] = possible_keys[0]
            else:
                key_stream[pos] = 0x20  # 默认空格对应的密钥
    
    # 还原所有明文
    result_plaintexts = []
    for i in range(num_ct):
        pt = bytes([c_bytes[i][j] ^ key_stream[j] for j in range(len(c_bytes[i]))])
        result_plaintexts.append(pt.decode('utf-8', errors='replace'))
    
    return result_plaintexts, key_stream

# 执行解密
plaintexts, key = infer_key_and_plaintext(ciphertexts_hex)

# 输出结果
print("=== 各密文解密结果 ===")
for i, pt in enumerate(plaintexts):
    if i == 10:
        print(f"\n🎯 目标密文解密结果:")
    else:
        print(f"\n密文 #{i+1} 解密结果:")
    print(pt)

# 输出密钥流（十六进制）
print("\n=== 推断出的密钥流（十六进制） ===")
key_hex = binascii.hexlify(bytes(key)).decode('utf-8')
print(key_hex)