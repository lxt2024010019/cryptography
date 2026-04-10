#!/usr/bin/env python3
"""
Lab2: 多次填充攻击流密码 - 改进版
利用多段密文和空格模式精确恢复密钥流，解密目标密文
"""

import binascii
from collections import Counter
from typing import List, Optional

# 所有密文（十六进制字符串）
ciphers_hex = [
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
    # 目标密文（第11段）
    "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
]

def hex_to_bytes(hex_str: str) -> bytes:
    return binascii.unhexlify(hex_str)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    min_len = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(min_len))

def is_printable(b: int) -> bool:
    return 32 <= b <= 126 or b in (9, 10)

def is_letter(b: int) -> bool:
    return 65 <= b <= 90 or 97 <= b <= 122

def is_space(b: int) -> bool:
    return b == 32

def recover_key_stream(ciphers: List[bytes]) -> bytes:
    """精确恢复密钥流"""
    max_len = max(len(c) for c in ciphers)
    key = [None] * max_len
    plain = [[None] * len(c) for c in ciphers]

    # 辅助函数：尝试从异或值推断空格模式
    def try_space_pattern(xor_val: int):
        candidates = []
        for letter in range(65, 123):
            if is_letter(letter):
                if (32 ^ letter) == xor_val:
                    candidates.append((32, letter))
                if (letter ^ 32) == xor_val:
                    candidates.append((letter, 32))
        return candidates

    # 多轮迭代
    for _ in range(20):
        changed = False
        for pos in range(max_len):
            if key[pos] is not None:
                continue
            # 收集该位置所有密文
            c_vals = [(i, c[pos]) for i, c in enumerate(ciphers) if pos < len(c)]
            if len(c_vals) < 2:
                continue

            # 统计密钥候选
            key_cand = Counter()

            # 利用已知明文推断
            for i, c in c_vals:
                if plain[i][pos] is not None:
                    key_cand[c ^ plain[i][pos]] += 5

            # 利用异或值推断
            for idx1 in range(len(c_vals)):
                for idx2 in range(idx1+1, len(c_vals)):
                    i1, c1 = c_vals[idx1]
                    i2, c2 = c_vals[idx2]
                    xor_val = c1 ^ c2

                    # 空格模式
                    for p1, p2 in try_space_pattern(xor_val):
                        # 可能性1: (i1,p1), (i2,p2)
                        k1 = c1 ^ p1
                        k2 = c2 ^ p2
                        if k1 == k2:
                            key_cand[k1] += 3
                        # 可能性2: (i1,p2), (i2,p1)
                        k1 = c1 ^ p2
                        k2 = c2 ^ p1
                        if k1 == k2:
                            key_cand[k1] += 3

            if key_cand:
                best_key, best_cnt = key_cand.most_common(1)[0]
                # 需要足够证据
                if best_cnt >= 4:
                    key[pos] = best_key
                    changed = True
                    # 更新所有明文
                    for i, c in c_vals:
                        plain[i][pos] = c ^ best_key

        if not changed:
            break

    # 未恢复的位置用最常见的密钥值填充
    valid_keys = [k for k in key if k is not None]
    if valid_keys:
        common = Counter(valid_keys).most_common(1)[0][0]
        key = [common if k is None else k for k in key]
    else:
        key = [0] * max_len

    return bytes(key)

def main():
    ciphers = [hex_to_bytes(h) for h in ciphers_hex]
    target = ciphers[-1]
    others = ciphers[:-1]

    print("恢复密钥流...")
    keystream = recover_key_stream(others)
    print(f"密钥流长度: {len(keystream)} 字节")

    # 解密目标
    plain = bytes(target[i] ^ keystream[i] for i in range(len(target)))
    print("\n解密结果（可打印字符）:")
    result_str = ''.join(chr(b) if is_printable(b) else '?' for b in plain)
    print(result_str)

    # 完整输出
    print("\n完整十六进制:")
    print(plain.hex())

    # 保存结果
    with open("decrypted_result.txt", "w") as f:
        f.write("目标密文解密结果:\n")
        f.write(result_str + "\n\n")
        f.write("十六进制:\n" + plain.hex() + "\n")
        f.write("密钥流:\n" + keystream.hex() + "\n")

if __name__ == "__main__":
    main()