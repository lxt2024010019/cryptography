from Crypto.Cipher import AES

def aes_cbc_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    Decrypts a ciphertext encrypted with AES-CBC mode.
    The ciphertext is expected to have the 16-byte IV prepended.
    PKCS#7 padding is removed after decryption.

    Args:
        key_hex: Hexadecimal string of the AES key (16 bytes).
        ciphertext_hex: Hexadecimal string of the IV + actual ciphertext.

    Returns:
        Decrypted plaintext as a UTF-8 string.
    """
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Extract IV (first 16 bytes) and the actual ciphertext blocks
    iv = ciphertext[:16]
    ct_blocks = ciphertext[16:]  # Length must be a multiple of 16

    # Create an AES ECB cipher object for block decryption
    cipher_ecb = AES.new(key, AES.MODE_ECB)

    prev_block = iv
    plaintext_blocks = []

    # Process each 16-byte ciphertext block
    for i in range(0, len(ct_blocks), 16):
        block = ct_blocks[i:i+16]
        decrypted = cipher_ecb.decrypt(block)          # AES decrypt the block
        plain_block = bytes(a ^ b for a, b in zip(decrypted, prev_block))  # XOR with previous ciphertext block (or IV)
        plaintext_blocks.append(plain_block)
        prev_block = block

    # Concatenate all decrypted blocks
    plaintext_padded = b''.join(plaintext_blocks)

    # Remove PKCS#7 padding
    pad_len = plaintext_padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    # Verify padding (optional, but good practice)
    if plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    plaintext = plaintext_padded[:-pad_len]

    return plaintext.decode('utf-8')


def aes_ctr_decrypt(key_hex: str, ciphertext_hex: str) -> str:
    """
    Decrypts a ciphertext encrypted with AES-CTR mode.
    The ciphertext is expected to have the 16-byte initial counter value prepended.
    No padding is used.

    Args:
        key_hex: Hexadecimal string of the AES key (16 bytes).
        ciphertext_hex: Hexadecimal string of the initial counter + actual ciphertext.

    Returns:
        Decrypted plaintext as a UTF-8 string.
    """
    key = bytes.fromhex(key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Extract initial counter (first 16 bytes)
    init_counter = ciphertext[:16]
    ct_bytes = ciphertext[16:]   # actual encrypted data

    # Interpret the counter as a 128-bit big-endian integer
    counter_int = int.from_bytes(init_counter, byteorder='big')
    cipher_ecb = AES.new(key, AES.MODE_ECB)

    plaintext_bytes = bytearray()
    # Process the ciphertext in 16-byte chunks (last chunk may be shorter)
    for i in range(0, len(ct_bytes), 16):
        # Current counter value as 16-byte big-endian bytes
        counter_bytes = counter_int.to_bytes(16, byteorder='big')
        # Encrypt the counter to produce the keystream block
        keystream = cipher_ecb.encrypt(counter_bytes)

        # Get the current ciphertext chunk (might be shorter than 16)
        chunk = ct_bytes[i:i+16]
        # XOR keystream with ciphertext to get plaintext
        plain_chunk = bytes(a ^ b for a, b in zip(keystream, chunk))
        plaintext_bytes.extend(plain_chunk)

        # Increment counter for next block
        counter_int += 1

    return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    # Provided test cases
    # Question 1: CBC mode
    key1 = "140b41b22a29beb4061bda66b6747e14"
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    plain1 = aes_cbc_decrypt(key1, cipher1)
    print("Q1 plaintext:", plain1)

    # Question 2: CBC mode
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    plain2 = aes_cbc_decrypt(key1, cipher2)
    print("Q2 plaintext:", plain2)

    # Question 3: CTR mode
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    plain3 = aes_ctr_decrypt(key3, cipher3)
    print("Q3 plaintext:", plain3)

    # Question 4: CTR mode
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
    plain4 = aes_ctr_decrypt(key3, cipher4)
    print("Q4 plaintext:", plain4)