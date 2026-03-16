def caesar_decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isupper():
            original_ascii = ord(char) - key
            if original_ascii < ord('A'):
                original_ascii += 26 
            plaintext += chr(original_ascii)
        else:
            plaintext += char
    return plaintext
ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"
print("=== 凯撒密码穷举解密结果 ===")
correct_key = None
correct_plaintext = None
for k in range(1, 26):
    result = caesar_decrypt(ciphertext, k)
    print(f"k={k:2d}  : {result}")
    if result == "LEARNINGPYTHONISINTERESTING":
        correct_key = k
        correct_plaintext = result
print("\n=== 正确解密结果 ===")
print(f"正确密钥 k = {correct_key}")
print(f"解密后的明文 = {correct_plaintext}")