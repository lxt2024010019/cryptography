# 第一题

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

#题目1：CBC模式解密
print("=== 题目1：CBC模式解密 ===")
print("="*50)

#参数
key_hex = "140b41b22a29beb4061bda66b6747e14"
cipher_hex = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"

#转换为字节
key = binascii.unhexlify(key_hex)
cipher_bytes = binascii.unhexlify(cipher_hex)

print(f"密钥: {key_hex}")
print(f"密钥长度: {len(key)} 字节")
print(f"密文长度: {len(cipher_bytes)} 字节")

#CBC解密步骤
#1. 提取前16字节作为IV
iv = cipher_bytes[:16]
ciphertext = cipher_bytes[16:]

print(f"\nIV (16字节): {binascii.hexlify(iv).decode()}")
print(f"实际密文长度: {len(ciphertext)} 字节")

#2. 创建AES-CBC解密器
aes = AES.new(key, AES.MODE_CBC, iv)

#3. 解密
decrypted = aes.decrypt(ciphertext)

print(f"\n解密结果 (带填充):")
print(f"十六进制: {binascii.hexlify(decrypted).decode()}")

#4. 去除PKCS7填充
plaintext = unpad(decrypted, 16)

print(f"\n去除填充后:")
print(f"十六进制: {binascii.hexlify(plaintext).decode()}")
print(f"明文长度: {len(plaintext)} 字节")

#5. 解码为字符串
result = plaintext.decode('utf-8')
print(f"\n解密结果: {result}")
print("="*50)


# 第二题
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

#题目2：CBC模式解密
print("\n=== 题目2：CBC模式解密 ===")
print("="*50)

#参数
key_hex = "140b41b22a29beb4061bda66b6747e14"
cipher_hex = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

#转换为字节
key = binascii.unhexlify(key_hex)
cipher_bytes = binascii.unhexlify(cipher_hex)

print(f"密钥: {key_hex}")
print(f"密钥长度: {len(key)} 字节")
print(f"密文长度: {len(cipher_bytes)} 字节")

#CBC解密步骤
#1. 提取前16字节作为IV
iv = cipher_bytes[:16]
ciphertext = cipher_bytes[16:]

print(f"\nIV (16字节): {binascii.hexlify(iv).decode()}")
print(f"实际密文长度: {len(ciphertext)} 字节")

#2. 创建AES-CBC解密器
aes = AES.new(key, AES.MODE_CBC, iv)

#3. 解密
decrypted = aes.decrypt(ciphertext)

print(f"\n解密结果 (带填充):")
print(f"十六进制: {binascii.hexlify(decrypted).decode()}")

#4. 去除PKCS7填充
plaintext = unpad(decrypted, 16)

print(f"\n去除填充后:")
print(f"十六进制: {binascii.hexlify(plaintext).decode()}")
print(f"明文长度: {len(plaintext)} 字节")

#5. 解码为字符串
result = plaintext.decode('utf-8')
print(f"\n解密结果: {result}")
print("="*50)


# 第三题
from Crypto.Cipher import AES
import binascii

#题目3：CTR模式解密
print("\n=== 题目3：CTR模式解密 ===")
print("="*50)

#参数
key_hex = "36f18357be4dbd77f050515c73fcf9f2"
cipher_hex = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"

#转换为字节
key = binascii.unhexlify(key_hex)
cipher_bytes = binascii.unhexlify(cipher_hex)

print(f"密钥: {key_hex}")
print(f"密钥长度: {len(key)} 字节")
print(f"密文长度: {len(cipher_bytes)} 字节")

#CTR解密步骤
#1. 提取前16字节作为初始计数器值
initial_counter_bytes = cipher_bytes[:16]
ciphertext = cipher_bytes[16:]

print(f"\n初始计数器值 (16字节): {binascii.hexlify(initial_counter_bytes).decode()}")
print(f"实际密文长度: {len(ciphertext)} 字节")

#2. 将初始计数器值转换为整数
initial_counter = int.from_bytes(initial_counter_bytes, 'big')
print(f"初始计数器值 (整数): {initial_counter}")

#3. 创建AES-ECB加密器用于生成密钥流
cipher = AES.new(key, AES.MODE_ECB)

#4. 解密
plaintext_bytes = b""

for i in range(0, len(ciphertext), 16):
    #当前计数器值 = 初始值 + 块索引
    current_counter = initial_counter + (i // 16)
    
    #将计数器转换为16字节
    counter_bytes = current_counter.to_bytes(16, 'big')
    
    #AES加密计数器得到密钥流
    keystream = cipher.encrypt(counter_bytes)
    
    #获取当前密文块
    cipher_block = ciphertext[i:i+16]
    
    #密钥流与密文异或得到明文
    keystream_block = keystream[:len(cipher_block)]
    plaintext_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
    plaintext_bytes += plaintext_block

print(f"\n解密结果:")
print(f"十六进制: {binascii.hexlify(plaintext_bytes).decode()}")
print(f"明文长度: {len(plaintext_bytes)} 字节")

#5. 解码为字符串
result = plaintext_bytes.decode('utf-8')
print(f"\n解密结果: {result}")
print("="*50)


# 第四题
from Crypto.Cipher import AES
import binascii

#题目4：CTR模式解密（第二个）
print("\n=== 题目4：CTR模式解密（第二个）===")
print("="*50)

#参数
key_hex = "36f18357be4dbd77f050515c73fcf9f2"
cipher_hex = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

#转换为字节
key = binascii.unhexlify(key_hex)
cipher_bytes = binascii.unhexlify(cipher_hex)

print(f"密钥: {key_hex}")
print(f"密钥长度: {len(key)} 字节")
print(f"密文长度: {len(cipher_bytes)} 字节")

#CTR解密步骤
#1. 提取前16字节作为初始计数器值
initial_counter_bytes = cipher_bytes[:16]
ciphertext = cipher_bytes[16:]

print(f"\n初始计数器值 (16字节): {binascii.hexlify(initial_counter_bytes).decode()}")
print(f"实际密文长度: {len(ciphertext)} 字节")

#2. 将初始计数器值转换为整数
initial_counter = int.from_bytes(initial_counter_bytes, 'big')
print(f"初始计数器值 (整数): {initial_counter}")

#3. 创建AES-ECB加密器用于生成密钥流
cipher = AES.new(key, AES.MODE_ECB)

#4. 解密
plaintext_bytes = b""

for i in range(0, len(ciphertext), 16):
    #当前计数器值 = 初始值 + 块索引
    current_counter = initial_counter + (i // 16)
    
    #将计数器转换为16字节
    counter_bytes = current_counter.to_bytes(16, 'big')
    
    #AES加密计数器得到密钥流
    keystream = cipher.encrypt(counter_bytes)
    
    #获取当前密文块
    cipher_block = ciphertext[i:i+16]
    
    #密钥流与密文异或得到明文
    keystream_block = keystream[:len(cipher_block)]
    plaintext_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
    plaintext_bytes += plaintext_block

print(f"\n解密结果:")
print(f"十六进制: {binascii.hexlify(plaintext_bytes).decode()}")
print(f"明文长度: {len(plaintext_bytes)} 字节")

#5. 解码为字符串
result = plaintext_bytes.decode('utf-8')
print(f"\n解密结果: {result}")
print("="*50)