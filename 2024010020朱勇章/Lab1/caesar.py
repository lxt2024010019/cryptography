# 密文: NUFECMWBYUJMBIQGYNBYWIXY

def caesar_decrypt(ciphertext, k):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha() and char.isupper():
            decrypted_char = chr((ord(char) - ord('A') - k) % 26 + ord('A'))
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext

cipher = "NUFECMWBYUJMBIQGYNBYWIXY"

print("===== 穷举法破解凯撒密码结果 =====")
for k in range(1, 26):
    result = caesar_decrypt(cipher, k)
    print(f"k={k:<2} : {result}")

"""
