#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lab2: 多次填充攻击流密码
目标：利用11段使用相同流密码密钥加密的密文，通过多次填充攻击解密最后一段目标密文。
"""

import binascii
from typing import List

class ManyTimePadAttack:
    def __init__(self, ciphertexts: List[str]):
        """
        初始化攻击器
        :param ciphertexts: 十六进制字符串格式的密文列表，最后一条是目标密文
        """
        # 将所有密文转换为字节数组
        self.ciphertexts = [binascii.unhexlify(ct) for ct in ciphertexts]
        # 最长的密文长度
        self.max_len = max(len(ct) for ct in self.ciphertexts)
        # 假设的明文矩阵，初始为None
        self.guessed_plaintexts = [bytearray(b'?' * len(ct)) for ct in self.ciphertexts]
        # 推导出的密钥流，长度与最长密文一致
        self.key_stream = bytearray(b'\x00' * self.max_len)

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """对两个字节序列进行异或，长度以较短者为准"""
        return bytes([x ^ y for x, y in zip(a, b)])

    def is_printable_ascii(self, char_code: int) -> bool:
        """判断一个ASCII码是否为可打印字符（包括空格）"""
        return 32 <= char_code <= 126  # 空格到波浪线

    def analyze_with_space(self):
        """
        核心分析函数：利用“空格与字母异或会翻转大小写”的特性进行攻击
        该方法遍历所有密文对，检查异或结果是否符合字母与空格异或的规律。
        """
        # 步骤1: 遍历所有可能的位置
        for pos in range(self.max_len):
            # 用于统计在该位置上，哪些密文可能包含空格
            space_count = [0] * len(self.ciphertexts)
            
            # 步骤2: 遍历所有密文对 (i, j)
            for i in range(len(self.ciphertexts)):
                # 如果密文i在此位置无字符，则跳过
                if pos >= len(self.ciphertexts[i]):
                    continue
                    
                for j in range(len(self.ciphertexts)):
                    if i == j:
                        continue
                    # 如果密文j在此位置无字符，则跳过
                    if pos >= len(self.ciphertexts[j]):
                        continue
                    
                    # 计算两个密文在该位置的异或值
                    xor_val = self.ciphertexts[i][pos] ^ self.ciphertexts[j][pos]
                    
                    # 关键判断: 如果异或结果是0，说明两个明文字符相同（可能性较小）
                    # 如果异或结果是0x20（空格与字母异或的特征值）或其他可打印字符范围
                    if xor_val == 0:
                        # 可能是两个相同字符，但无法确定是什么
                        pass
                    elif 0x40 <= xor_val <= 0x5A or 0x60 <= xor_val <= 0x7A:
                        # 如果异或结果在大写或小写字母的ASCII范围内
                        # 尝试猜测其中一个是空格(0x20)，另一个是字母
                        # 假设密文i的明文是空格(0x20)
                        guess_for_i = 0x20
                        guess_for_j = guess_for_i ^ xor_val
                        
                        # 验证猜测：如果猜测的j是字母，则计数
                        if 0x41 <= guess_for_j <= 0x5A or 0x61 <= guess_for_j <= 0x7A:
                            space_count[i] += 1
                            
                        # 假设密文j的明文是空格(0x20)
                        guess_for_j = 0x20
                        guess_for_i = guess_for_j ^ xor_val
                        
                        # 验证猜测：如果猜测的i是字母，则计数
                        if 0x41 <= guess_for_i <= 0x5A or 0x61 <= guess_for_i <= 0x7A:
                            space_count[j] += 1
            
            # 步骤3: 对每个位置，找出最可能包含空格的密文
            # 如果某个密文在此位置被多次“投票”为包含空格，则采纳
            for idx in range(len(self.ciphertexts)):
                if pos < len(self.ciphertexts[idx]) and space_count[idx] > 0:
                    # 这里可以设置一个阈值，比如大于密文数量的一半
                    # 简单起见，我们只要有投票就采纳
                    if space_count[idx] > len(self.ciphertexts) // 3:
                        # 猜测这个位置是空格
                        self.guessed_plaintexts[idx][pos] = 0x20
                        # 通过 密文 ⊕ 明文 = 密钥流 推导密钥流
                        self.key_stream[pos] = self.ciphertexts[idx][pos] ^ 0x20

    def decrypt_with_known_key_stream(self):
        """使用推导出的密钥流解密所有密文（包括目标密文）"""
        for idx, cipher in enumerate(self.ciphertexts):
            for pos in range(len(cipher)):
                if pos < len(self.key_stream) and self.key_stream[pos] != 0:
                    # 如果此位置的密钥流已知，则解密
                    decrypted_char = cipher[pos] ^ self.key_stream[pos]
                    if self.is_printable_ascii(decrypted_char):
                        self.guessed_plaintexts[idx][pos] = decrypted_char

    def manual_refinement(self):
        """
        手动修正阶段：基于已知的单词和上下文，手动推测部分字符
        这是一个交互式过程，可以根据输出结果进行优化
        """
        # 这里可以根据初步的解密结果进行手动修正
        # 例如，如果我们看到"Th?"，可以推测可能是"The"
        
        # 示例：基于英语单词的常见模式进行修正
        common_words = ['the', 'and', 'that', 'have', 'for', 'not', 'with', 'this', 'but', 'from']
        
        for idx, plaintext in enumerate(self.guessed_plaintexts):
            plaintext_str = plaintext.decode('ascii', errors='ignore')
            # 可以在这里添加自动或手动的模式匹配和修正逻辑
            # 例如，将"?he"替换为"The"
            
            # 简单的示例修正（实际中需要更复杂的逻辑或人工干预）
            if '?he' in plaintext_str:
                # 找到位置并更新密钥流
                pass

    def run_attack(self):
        """执行完整攻击流程"""
        print("开始多次填充攻击...")
        print(f"密文数量: {len(self.ciphertexts)}")
        print(f"最大密文长度: {self.max_len}")
        
        # 步骤1: 使用空格分析技术
        print("\n[步骤1] 使用空格-字母异或规律进行分析...")
        self.analyze_with_space()
        
        # 步骤2: 用已知密钥流解密
        print("[步骤2] 使用推导的密钥流进行解密...")
        self.decrypt_with_known_key_stream()
        
        # 步骤3: 显示初步结果
        print("\n[步骤3] 初步解密结果:")
        for i, plaintext in enumerate(self.guessed_plaintexts):
            plaintext_str = plaintext.decode('ascii', errors='ignore')
            print(f"密文 #{i+1:2d}: {plaintext_str}")
        
        # 步骤4: 目标密文结果
        target_idx = len(self.ciphertexts) - 1
        target_plaintext = self.guessed_plaintexts[target_idx].decode('ascii', errors='ignore')
        print(f"\n🎯 目标密文解密结果: {target_plaintext}")
        
        return target_plaintext

def main():
    # 从文档中复制的密文（十六进制字符串）
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
        # 目标密文
        "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
    ]
    
    # 创建攻击器实例并执行攻击
    attacker = ManyTimePadAttack(ciphertexts_hex)
    result = attacker.run_attack()
    
    # 保存结果到文件
    with open('decryption_result.txt', 'w', encoding='utf-8') as f:
        f.write(f"目标密文解密结果: {result}\n\n")
        f.write("所有密文解密结果:\n")
        for i, plaintext in enumerate(attacker.guessed_plaintexts):
            plaintext_str = plaintext.decode('ascii', errors='ignore')
            f.write(f"密文 #{i+1:2d}: {plaintext_str}\n")

if __name__ == "__main__":
    main()
