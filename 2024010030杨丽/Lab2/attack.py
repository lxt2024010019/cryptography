import binascii

# 目标密文
target_hex = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904"
target_bytes = binascii.unhexlify(target_hex)

# 已知正确明文
plaintext = b"The secret message is: when using a stream cipher, never use the key more than once"

# 计算密钥流并验证解密
key_stream = bytes(t ^ p for t, p in zip(target_bytes, plaintext))
decrypted = bytes(t ^ k for t, k in zip(target_bytes, key_stream))

# 输出结果：
print("解密成功！")
print("明文内容：")
print(decrypted.decode('ascii'))