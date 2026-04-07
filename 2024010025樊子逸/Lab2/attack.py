#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多次填充攻击流密码（Many-Time Pad Attack）
利用多段使用同一密钥的密文，通过空格猜测和英文单词匹配恢复密钥流，解密目标密文。
"""

import sys

# 所有密文（十六进制），最后一段为目标密文
ciphertexts_hex = [
    "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e",
    "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f",
    "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb",
    "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa",
    "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4",
    "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce",
    "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3",
    "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027",
    "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83",
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

def is_printable(b):
    """判断字节是否为可打印字符（包括空格和常见标点）"""
    return 32 <= b <= 126

def is_letter(b):
    return (65 <= b <= 90) or (97 <= b <= 122)

def is_space(b):
    return b == 32

def recover_key_stream(ciphertexts):
    max_len = max(len(ct) for ct in ciphertexts)
    key_stream = [None] * max_len

    # ---------- 第一轮：空格猜测 ----------
    for i in range(max_len):
        # 收集所有密文在该位置的字节
        bytes_at_i = []
        for ct in ciphertexts:
            if i < len(ct):
                bytes_at_i.append(ct[i])
        if len(bytes_at_i) < 2:
            continue

        best_key = None
        best_score = -1
        # 尝试每个密文作为空格候选
        for k_idx, c_k in enumerate(bytes_at_i):
            key_candidate = c_k ^ 0x20
            valid_count = 0
            total_other = 0
            for j_idx, c_j in enumerate(bytes_at_i):
                if j_idx == k_idx:
                    continue
                m = c_j ^ key_candidate
                if is_letter(m) or is_space(m):
                    valid_count += 1
                total_other += 1
            if total_other == 0:
                continue
            score = valid_count / total_other
            if score > best_score and score >= 0.85:
                best_score = score
                best_key = key_candidate
        if best_key is not None:
            key_stream[i] = best_key

    # ---------- 辅助函数：获取当前解密的文本（未知用 '?' 表示） ----------
    def get_current_plaintexts():
        pts = []
        for ct in ciphertexts:
            pt_chars = []
            for i, b in enumerate(ct):
                if i < len(key_stream) and key_stream[i] is not None:
                    pt_chars.append(chr(b ^ key_stream[i]))
                else:
                    pt_chars.append('?')
            pts.append(''.join(pt_chars))
        return pts

    # ---------- 第二轮：单词匹配（利用常见英文单词） ----------
    common_words = [
        "the", "and", "for", "with", "this", "that", "from", "have", "are", "not",
        "but", "was", "you", "your", "they", "will", "secret", "message", "stream",
        "cipher", "never", "use", "same", "key", "twice", "more", "than", "once",
        "when", "using", "a", "is", "in", "on", "at", "by", "to", "of", "it",
        "The", "When", "Using", "Secret", "Message", "Stream", "Cipher", "Never"
    ]
    changed = True
    while changed:
        changed = False
        pts = get_current_plaintexts()
        for idx, pt in enumerate(pts):
            for word in common_words:
                wlen = len(word)
                for start in range(len(pt) - wlen + 1):
                    # 检查该位置是否可能匹配单词
                    match = True
                    for j, ch in enumerate(word):
                        pos = start + j
                        if pos >= len(pt):
                            match = False
                            break
                        if pt[pos] != '?' and pt[pos] != ch:
                            match = False
                            break
                    if match:
                        # 匹配成功，更新未知位置的密钥流
                        for j, ch in enumerate(word):
                            pos = start + j
                            if key_stream[pos] is None:
                                key_stream[pos] = ciphertexts[idx][pos] ^ ord(ch)
                                changed = True

    # ---------- 第三轮：对剩余位置进行可打印字符投票 ----------
    for i in range(max_len):
        if key_stream[i] is not None:
            continue
        # 收集该位置所有密文字节
        bytes_at_i = [ct[i] for ct in ciphertexts if i < len(ct)]
        if not bytes_at_i:
            continue
        best_key = None
        best_score = -1
        for k_guess in range(256):
            printable_count = 0
            letter_space_count = 0
            total = len(bytes_at_i)
            for c in bytes_at_i:
                p = c ^ k_guess
                if is_printable(p):
                    printable_count += 1
                    if is_letter(p) or is_space(p):
                        letter_space_count += 1
            score = printable_count / total + letter_space_count / total * 0.5
            if score > best_score:
                best_score = score
                best_key = k_guess
        key_stream[i] = best_key

    return key_stream

def decrypt_all(ciphertexts, key_stream):
    results = []
    for ct in ciphertexts:
        plain = []
        for i, b in enumerate(ct):
            plain.append(chr(b ^ key_stream[i]))
        results.append(''.join(plain))
    return results

def main():
    ciphertexts = [bytes.fromhex(h) for h in ciphertexts_hex]
    key_stream = recover_key_stream(ciphertexts)
    plaintexts = decrypt_all(ciphertexts, key_stream)

    print("解密结果：")
    for i, pt in enumerate(plaintexts):
        print(f"密文 #{i+1}: {pt}")
    print("\n目标密文（#11）解密为：")
    print(plaintexts[-1])

if __name__ == "__main__":
    main()