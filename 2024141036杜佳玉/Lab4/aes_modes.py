# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def cbc_decrypt(ciphertext_hex, key_hex):
    """
    AES CBC 模式解密
    """
    # 1. 将十六进制字符串转换为字节
    ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
    key_bytes = binascii.unhexlify(key_hex)

    # 2. 提取 IV (前 16 个字节) 和 实际密文 (剩余部分)
    iv = ciphertext_bytes[:16]
    actual_ciphertext = ciphertext_bytes[16:]

    # 3. 创建 AES 解密器
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

    # 4. 解密
    decrypted_padded = cipher.decrypt(actual_ciphertext)

    # 5. 去除 PKCS#7 填充
    decrypted_text = unpad(decrypted_padded, AES.block_size)

    return decrypted_text.decode('utf-8')

# --- 主程序 ---
if __name__ == "__main__":
    # 第 1 题的密钥
    key_hex = "140b41b22a29beb4061bda66b6747e14"

    # 第 1 题的密文 (已合并为一行)
    ciphertext_hex = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

    try:
        result = cbc_decrypt(ciphertext_hex, key_hex)
        print(f"解密结果: {result}")
    except Exception as e:
        print(f"解密失败: {e}")


# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def cbc_decrypt(ciphertext_hex, key_hex):
    """
    AES CBC 模式解密
    """
    # 1. 将十六进制字符串转换为字节
    ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
    key_bytes = binascii.unhexlify(key_hex)

    # 2. 提取 IV (前 16 个字节) 和 实际密文 (剩余部分)
    iv = ciphertext_bytes[:16]
    actual_ciphertext = ciphertext_bytes[16:]

    # 3. 创建 AES 解密器
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

    # 4. 解密
    decrypted_padded = cipher.decrypt(actual_ciphertext)

    # 5. 去除 PKCS#7 填充
    decrypted_text = unpad(decrypted_padded, AES.block_size)

    return decrypted_text.decode('utf-8')

# --- 主程序 ---
if __name__ == "__main__":
    # 第 2 题的密钥 (与第 1 题相同)
    key_hex = "140b41b22a29beb4061bda66b6747e14"

    # 第 2 题的密文
    ciphertext_hex = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    try:
        result = cbc_decrypt(ciphertext_hex, key_hex)
        print(f"解密结果: {result}")
    except Exception as e:
        print(f"解密失败: {e}")



# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
import binascii

def ctr_decrypt(ciphertext_hex, key_hex):
    # 1. 数据转换
    ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
    key_bytes = binascii.unhexlify(key_hex)

    # 2. 提取 IV (前 16 字节)
    # 这里的逻辑是：密文的前16字节是 Counter Block
    iv = ciphertext_bytes[:16]
    actual_ciphertext = ciphertext_bytes[16:]

    # 3. 核心修正：使用 AES.new 的 counter 参数或手动构造
    # 很多题目使用的是简单的 "前16字节作为初始计数器值" 的逻辑
    # 我们需要构造一个 counter 函数来匹配这种行为

    # 方法：直接传入 initial_value 和 little_endian 设置通常比较麻烦
    # 最稳妥的方式是利用 AES.new 的 counter 参数 (如果版本支持)
    # 或者更通用的方式：使用 mode_ctr (但在 PyCryptodome 中通常用以下方式)

    try:
        # 尝试方式 A：直接指定 nonce (如果库版本较新且逻辑匹配)
        # 注意：如果报错或乱码，说明题目使用的是 "Initial Value" 逻辑而非 "Nonce+Counter" 逻辑
        cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=b'', initial_value=iv)
    except TypeError:
        # 尝试方式 B：兼容旧逻辑，把 iv 当作整个 counter block
        # 这通常需要自定义 counter 函数，但在 PyCryptodome 中，
        # 最接近题目意图的通常是下面这种 "Nonce 为空，IV 全作为初始值" 的写法
        # 或者题目其实是把前16字节当作 nonce（但这在CTR里很不常见）

        # 让我们尝试最暴力且通用的修正：
        # 假设题目只是简单的把前16字节作为计数器初始块
        cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))

    decrypted_bytes = cipher.decrypt(actual_ciphertext)
    return decrypted_bytes.decode('utf-8', errors='replace')

if __name__ == "__main__":
    key_hex = "36f18357be4dbd77f050515c73fcf9f2"
    ciphertext_hex = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

    try:
        result = ctr_decrypt(ciphertext_hex, key_hex)
        print("解密结果:", result)
    except Exception as e:
        print("解密出错:", str(e))





# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
import binascii

def ctr_decrypt(ciphertext_hex, key_hex):
    """
    AES CTR 模式解密
    适配题目逻辑：前16字节作为初始计数器值 (Initial Value)
    """
    # 1. 将十六进制字符串转换为字节
    ciphertext_bytes = binascii.unhexlify(ciphertext_hex)
    key_bytes = binascii.unhexlify(key_hex)

    # 2. 提取 IV (前 16 个字节) 和 实际密文 (剩余部分)
    iv = ciphertext_bytes[:16]
    actual_ciphertext = ciphertext_bytes[16:]

    # 3. 创建 AES CTR 解密器
    # 关键点：设置 nonce 为空，将前 16 字节作为 initial_value (大端序)
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big'))

    # 4. 解密
    decrypted_bytes = cipher.decrypt(actual_ciphertext)

    return decrypted_bytes.decode('utf-8')

# --- 主程序 ---
if __name__ == "__main__":
    # 第 4 题的密钥 (与第 3 题相同)
    key_hex = "36f18357be4dbd77f050515c73fcf9f2"

    # 第 4 题的密文
    ciphertext_hex = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    try:
        result = ctr_decrypt(ciphertext_hex, key_hex)
        print("解密结果:", result)
    except Exception as e:
        print("解密失败:", str(e))