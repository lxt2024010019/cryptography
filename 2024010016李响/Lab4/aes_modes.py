from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import binascii

# ===================== AES CBC 解密（实验标准） =====================
def aes_cbc_decrypt(key_hex, ciphertext_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 提取前16字节作为IV
    iv = ciphertext[:16]
    actual_cipher = ciphertext[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(actual_cipher), AES.block_size)
    return plaintext.decode('utf-8')

# ===================== AES CTR 解密（修复版，适配16字节初始计数器） =====================
def aes_ctr_decrypt(key_hex, ciphertext_hex):
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)
    
    # 提取前16字节作为初始计数器值
    counter_initial = ciphertext[:16]
    actual_cipher = ciphertext[16:]
    
    # 拆分为 8字节nonce + 8字节初始值，用Counter对象实现CTR模式
    nonce = counter_initial[:8]
    initial_value = int.from_bytes(counter_initial[8:], byteorder='big')
    counter = Counter.new(64, prefix=nonce, initial_value=initial_value)
    
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(actual_cipher)
    return plaintext.decode('utf-8')

# ===================== 题目测试 =====================
if __name__ == "__main__":
    print("========== Lab4 答案 ==========\n")

    # 第1题 CBC
    key1 = "140b41b22a29beb4061bda66b6747e14"
    ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("第1题 CBC 明文：")
    print(aes_cbc_decrypt(key1, ct1), "\n")

    # 第2题 CBC
    ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("第2题 CBC 明文：")
    print(aes_cbc_decrypt(key1, ct2), "\n")

    # 第3题 CTR
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
    ct3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("第3题 CTR 明文：")
    print(aes_ctr_decrypt(key2, ct3), "\n")

    # 第4题 CTR
    ct4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("第4题 CTR 明文：")
    print(aes_ctr_decrypt(key2, ct4), "\n")