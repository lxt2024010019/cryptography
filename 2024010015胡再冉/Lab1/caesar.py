def caesar_decrypt(cipher, k):
    plaintext = ""
    for char in cipher:
        if char.isupper():
            shifted = ord(char) - k
            if shifted < ord('A'):
                shifted += 26
            plaintext += chr(shifted)
        else:
            plaintext += char
    return plaintext

ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

for k in range(1, 26):
    result = caesar_decrypt(ciphertext, k)
    print(f"k={k:2d}: {result}")