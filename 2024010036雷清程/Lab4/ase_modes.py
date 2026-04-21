#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES CBC 和 CTR 模式加解密实现
学号姓名: 2024010006黄璇
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii


def aes_cbc_decrypt(key_hex: str, cipher_hex: str) -> str:
    """AES CBC 模式解密"""
    key = binascii.unhexlify(key_hex)
    cipher_bytes = binascii.unhexlify(cipher_hex)

    iv = cipher_bytes[:16]
    ciphertext = cipher_bytes[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted, 16)

    return plaintext.decode('utf-8')


def aes_ctr_decrypt(key_hex: str, cipher_hex: str) -> str:
    """AES CTR 模式解密"""
    key = binascii.unhexlify(key_hex)
    cipher_bytes = binascii.unhexlify(cipher_hex)

    initial_counter = cipher_bytes[:16]
    ciphertext = cipher_bytes[16:]

    aes_ecb = AES.new(key, AES.MODE_ECB)
    plaintext_bytes = b""

    for i in range(0, len(ciphertext), 16):
        current_counter = int.from_bytes(initial_counter, 'big') + (i // 16)
        counter_bytes = current_counter.to_bytes(16, 'big')
        keystream = aes_ecb.encrypt(counter_bytes)

        cipher_block = ciphertext[i:i + 16]
        keystream_block = keystream[:len(cipher_block)]
        plaintext_block = bytes(a ^ b for a, b in zip(cipher_block, keystream_block))
        plaintext_bytes += plaintext_block

    return plaintext_bytes.decode('utf-8')


def solve_all_questions():
    print("=== AES CBC 和 CTR 模式解密实验解答 ===")
    print("=" * 60)

    # 第1题 CBC
    print("\n第1题 CBC 解密")
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    print("解密结果:", aes_cbc_decrypt(key1, cipher1))

    # 第2题 CBC
    print("\n第2题 CBC 解密")
    key2 = "140b41b22a29beb4061bda66b6747e14"
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    print("解密结果:", aes_cbc_decrypt(key2, cipher2))

    # 第3题 CTR
    print("\n第3题 CTR 解密")
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    print("解密结果:", aes_ctr_decrypt(key3, cipher3))

    # 第4题 CTR
    print("\n第4题 CTR 解密")
    key4 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    print("解密结果:", aes_ctr_decrypt(key4, cipher4))

    print("\n" + "=" * 60)


if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        print("✓ pycryptodome 已安装")
    except ImportError:
        print("请安装依赖：pip install pycryptodome")
        exit(1)

    solve_all_questions()