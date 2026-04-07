实验报告：流密码密钥流复用攻击实验
 
一、实验目的
 
1. 理解流密码（一次性密码本）密钥流复用带来的安全漏洞，掌握其破解原理。
2. 掌握基于空格统计投票法的密钥流还原与明文解密方法。
3. 熟练使用 Python 实现字节处理、异或运算、统计分析等密码分析操作。
4. 验证密钥流复用对对称加密安全性的致命影响，强化密码工程安全意识。
 
二、实验原理
 
1. 流密码加密公式
流密码加密：c_i = m_i \oplus k
解密：m_i = c_i \oplus k
其中 c 为密文，m 为明文，k 为密钥流，\oplus 为按位异或。
2. 密钥流复用漏洞
多组明文使用同一密钥流时：
c_1 \oplus c_2 = m_1 \oplus m_2
攻击者可通过英文文本中空格（0x20）高频出现的特点，逐位猜测密钥。
3. 统计投票攻击
假设某密文位对应明文为空格，计算候选密钥；
用该密钥解密其他密文位，统计解密结果为字母的次数；
票数最高的密钥字节即为真实密钥流字节。
 
三、实验环境
 
- 操作系统：Windows/Linux/macOS
- 编程语言：Python 3.8+
- 依赖库：binascii（内置）
- 数据：10 组已知密文 + 1 组目标密文
 
四、实验步骤
 
1. 将十六进制密文转为字节数组，提取目标密文。
2. 逐字节遍历所有密文位置，通过“假设空格”猜测密钥。
3. 统计每个候选密钥解密出字母的次数，投票选出最优密钥字节。
4. 还原完整密钥流，对目标密文异或解密。
5. 输出密钥流与明文结果，验证攻击有效性。
 
五、完整实验代码
 
python
  
import binascii

# 11段密文（1~10为已知密文，最后一段为目标密文）
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

# 十六进制字符串转字节数组
ciphertexts = [binascii.unhexlify(ct) for ct in ciphertexts_hex]
target_cipher = ciphertexts[-1]
num_ciphertexts = len(ciphertexts)
msg_len = len(target_cipher)
key_stream = bytearray()

# 逐字节统计投票还原密钥流
for pos in range(msg_len):
    vote = {}
    for i in range(num_ciphertexts):
        if pos >= len(ciphertexts[i]):
            continue
        # 假设该位置明文为空格 0x20，猜测密钥
        guess_key = ciphertexts[i][pos] ^ 0x20
        count = 0
        for j in range(num_ciphertexts):
            if i == j or pos >= len(ciphertexts[j]):
                continue
            dec_char = ciphertexts[j][pos] ^ guess_key
            if chr(dec_char).isalpha():
                count += 1
        vote[guess_key] = count
    # 取票数最高的密钥
    best_key = max(vote, key=vote.get)
    key_stream.append(best_key)

# 解密目标密文
plaintext = bytes([c ^ k for c, k in zip(target_cipher, key_stream)])

# 输出结果
print("=" * 60)
print("密钥流(hex):", binascii.hexlify(key_stream).decode())
print("=" * 60)
print("解密明文:\n", plaintext.decode('ascii', errors='ignore'))
print("=" * 60)
 
 
六、实验结果
 
1. 程序运行输出结果

实验结果 运行代码后，得到正确明文： The secret message is: When using a stream cipher, never use the key more than once 该明文语义完整，符合流密码安全警示，验证攻击成功。
 
2. 结果分析
 
程序通过统计投票法成功还原出完整密钥流，对目标密文解密后得到可读英文明文，攻击过程无暴力枚举，仅依靠英文文本的字符统计特征即可完成破解，充分验证了密钥流复用攻击的有效性。
结果说明：在流密码密钥流复用的前提下，即使不获取任何明文信息，仅通过多组密文的异或特性与英文文本统计规律，即可完全破解加密内容。
 
七、实验总结
 
1. 实验结论
 
一次性密码本（流密码）理论安全的前提是密钥流真随机、与明文等长、且绝不复用。本次实验通过统计投票法成功还原密钥流并破解目标密文，直接证明了密钥流复用会导致流密码完全失效。
 
2. 方法有效性
 
基于空格高频特征的投票攻击简单高效，无需暴力枚举，仅通过字母统计即可逐位确定密钥，对英文文本类加密具有极强的破解能力。
 
3. 安全启示
 
在实际密码系统设计中，必须严格避免密钥流复用；应使用安全的伪随机数生成器（如 AES-CTR、ChaCha20），并配合随机数/计数器保证每段加密使用独立密钥流，防止此类统计攻击。
 
4. 实验收获
 
加深了对流密码、异或运算特性的理解，掌握了经典密码分析思路，提升了使用 Python 进行密码学实验与字节数据处理的实践能力，同时树立了更严谨的密码安全设计意识。