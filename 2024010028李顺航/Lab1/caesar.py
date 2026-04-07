def caesar_decrypt(ciphertext, k):
    """凯撒解密函数"""
    plaintext = []
    for c in ciphertext:
        if c.isupper():
            shifted = ord(c) - k
            if shifted < ord('A'):
                shifted += 26
            plaintext.append(chr(shifted))
        elif c.islower():
            shifted = ord(c) - k
            if shifted < ord('a'):
                shifted += 26
            plaintext.append(chr(shifted))
        else:
            plaintext.append(c)
    return ''.join(plaintext)

if __name__ == "__main__":
    cipher = "NUFECMWBYUJMBIQGYNBYMWIXY"
    
    print("密文:", cipher)
    print("=" * 50)
    print("穷举所有可能的密钥 k (1~25):\n")
    
    # 穷举所有可能的密钥
    for k in range(1, 26):
        plain = caesar_decrypt(cipher, k)
        print(f"k={k:2d}: {plain}")
    
    print("=" * 50)
    
    # 手动观察，找到有意义的英文文本
    # 看起来 k=20 解密出的文本最有意义
    correct_k = 20
    correct_plain = caesar_decrypt(cipher, correct_k)
    print(f"\n✅ 正确密钥与明文:")
    print(f"k={correct_k}: {correct_plain}")
    
    # 验证一下：如果加密回去应该得到原密文
    def caesar_encrypt(plaintext, k):
        """凯撒加密函数（验证用）"""
        ciphertext = []
        for c in plaintext:
            if c.isupper():
                shifted = ord(c) + k
                if shifted > ord('Z'):
                    shifted -= 26
                ciphertext.append(chr(shifted))
            elif c.islower():
                shifted = ord(c) + k
                if shifted > ord('z'):
                    shifted -= 26
                ciphertext.append(chr(shifted))
            else:
                ciphertext.append(c)
        return ''.join(ciphertext)
    
    # 验证
    verification = caesar_encrypt(correct_plain, correct_k)
    print(f"\n验证（加密回去）: {verification}")
    print(f"验证结果: {'✓ 正确' if verification == cipher else '✗ 错误'}")