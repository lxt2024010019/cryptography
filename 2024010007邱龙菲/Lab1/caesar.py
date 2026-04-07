ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

for k in range(1, 26):
    plaintext = ""
    for char in ciphertext:
        # 字母序号转换（A=0, B=1, ..., Z=25）
        num = ord(char) - ord('A')
        # 解密：(字母序号 - k) mod 26
        decrypted_num = (num - k) % 26
        # 转回字母
        decrypted_char = chr(decrypted_num + ord('A'))
        plaintext += decrypted_char
    print(f"k={k:2d} : {plaintext}")