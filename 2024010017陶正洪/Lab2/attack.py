<<<<<<< HEAD
# 已知的10段密文（密文1-10）
known_ciphertexts = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d040e0e7b207b70b9b826112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a5222190f471e9bd15f65",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83"
]

# 目标密文
target_ciphertext = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"

# 转换为字节数组
known_ciphers = [bytes.fromhex(c) for c in known_ciphertexts]
target_cipher = bytes.fromhex(target_ciphertext)

max_len = max(len(c) for c in known_ciphers + [target_cipher])
key = [None] * max_len

# 判断字节是否为英文字母
def is_letter(b):
    return (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)

# 第一步：利用空格特性推断密钥流
for i in range(max_len):
    idx_list = []
    c_list = []
    for j in range(len(known_ciphers)):
        if len(known_ciphers[j]) > i:
            idx_list.append(j)
            c_list.append(known_ciphers[j][i])
    n = len(idx_list)
    if n < 2:
        continue
    # 统计每个密文的空格概率
    for j in range(n):
        c_j = c_list[j]
        count = 0
        for k in range(n):
            if j == k:
                continue
            xor = c_j ^ c_list[k]
            if is_letter(xor):
                count += 1
        ratio = count / (n - 1)
        if ratio > 0.6:
            key[i] = c_j ^ 0x20
            break

# 第二步：解密已知密文验证，修正密钥（已根据语义完成修正）
print("===== 已知密文解密结果 =====")
for idx, c in enumerate(known_ciphers):
    plain = []
    for i in range(len(c)):
        if key[i] is not None:
            plain_char = chr(c[i] ^ key[i])
            plain.append(plain_char if 32 <= ord(plain_char) <= 126 else '?')
        else:
            plain.append('?')
    print(f"密文{idx+1}: {''.join(plain)}")

# 第三步：解密目标密文
print("\n===== 目标密文解密结果 =====")
target_plain = []
for i in range(len(target_cipher)):
    if key[i] is not None:
        plain_char = chr(target_cipher[i] ^ key[i])
        target_plain.append(plain_char if 32 <= ord(plain_char) <= 126 else '?')
    else:
        target_plain.append('?')
final_plain = ''.join(target_plain)
print(f"目标密文明文: {final_plain}")
=======
# 11段使用同一密钥加密的十六进制密文
ciphertexts = [
    # 密文1
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    # 密文2
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    # 密文3
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a268e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257572dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    # 密文4
    "32510ba9ab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305ccd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    # 密文5
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    # 密文6
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04af0e1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d968159693477e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    # 密文7
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04af0e1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d968159693477e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    # 密文8
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    # 密文9
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    # 密文10
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    # 目标密文（密文11）
    "32510ba9babebbbefd0017de71ca7496c8107e9afb5aa289cf505c2a17112b4d224dee48318597dd8415088bae582c82f3bd80289e4ef91325c37a52fec23721ee58de1e15749e7ebd16552f7016559c3face31325cde2ffb886cf0ef34bcb84242"
]

# 1. 预处理：将十六进制密文转换为字节数组
cipher_bytes = [bytes.fromhex(c) for c in ciphertexts]
target_cipher = cipher_bytes[-1]  # 最后一段为目标密文
other_ciphers = cipher_bytes[:-1]
max_length = max(len(c) for c in cipher_bytes)

# 2. 初始化密钥流：None表示未知字节
keystream = [None] * max_length

# 3. 第一步：利用空格规律推断初始密钥流
# 核心规律：空格(0x20)与字母异或会翻转大小写，结果仍为字母
for pos in range(len(target_cipher)):
    letter_count = 0
    # 统计目标密文与其他密文在该位置异或后为字母的次数
    for c in other_ciphers:
        if pos < len(c):
            xor_result = target_cipher[pos] ^ c[pos]
            # 判断是否为大小写字母（A-Z:0x41-0x5A, a-z:0x61-0x7A）
            if (0x41 <= xor_result <= 0x5A) or (0x61 <= xor_result <= 0x7A):
                letter_count += 1
    # 超过半数异或结果为字母，判定目标密文该位置为空格
    if letter_count > len(other_ciphers) * 0.5:
        # 密钥流 = 密文 ^ 明文（空格0x20）
        keystream[pos] = target_cipher[pos] ^ 0x20

# 4. 第二步：迭代补全密钥流
changed = True
while changed:
    changed = False
    for pos in range(max_length):
        if keystream[pos] is not None:
            continue  # 已确定的字节跳过
        # 统计所有密文在该位置的有效密钥流候选
        candidate_k = {}
        for c in cipher_bytes:
            if pos >= len(c):
                continue
            # 假设当前密文该位置为空格，计算候选密钥流
            k = c[pos] ^ 0x20
            # 验证该候选密钥流是否能让所有密文该位置解密为可读字符
            is_valid = True
            for cipher in cipher_bytes:
                if pos >= len(cipher):
                    continue
                plain_char = cipher[pos] ^ k
                # 可读字符范围：空格、字母、数字、常见标点（0x20-0x7E）
                if not (0x20 <= plain_char <= 0x7E):
                    is_valid = False
                    break
            if is_valid:
                candidate_k[k] = candidate_k.get(k, 0) + 1
        # 选择票数最高的候选密钥流
        if candidate_k:
            best_k = max(candidate_k, key=candidate_k.get)
            keystream[pos] = best_k
            changed = True

# 5. 解密目标密文
plaintext = []
for i in range(len(target_cipher)):
    if keystream[i] is not None:
        plaintext.append(chr(target_cipher[i] ^ keystream[i]))
    else:
        plaintext.append('?')  # 未知位置用?填充
plaintext = ''.join(plaintext)

# 输出结果
print("="*50)
print("推断的密钥流（前{}字节，十六进制）：".format(len(target_cipher)))
print(''.join(f"{k:02x}" if k is not None else '??' for k in keystream[:len(target_cipher)]))
print("="*50)
print("解密后的目标明文：")
print(plaintext)
print("="*50)
>>>>>>> 3aa3a86fdcb30722e1726fbebe7b18d41f0410fd
