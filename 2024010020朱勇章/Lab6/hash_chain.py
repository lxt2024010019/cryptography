from Crypto.Hash import SHA256

def calculate_hash_chain_root(file_path: str) -> str:
    with open(file_path, "rb") as f:
        file_binary = f.read()

    block_size = 1024
    blocks = []
    for i in range(0, len(file_binary), block_size):
        current_block = file_binary[i:i+block_size]
        blocks.append(current_block)

    reversed_blocks = blocks[::-1]
    prev_hash = b""

    for block in reversed_blocks:
        combined_data = block + prev_hash
        sha256_obj = SHA256.new(combined_data)
        prev_hash = sha256_obj.digest()

    root_hash_hex = prev_hash.hex()
    return root_hash_hex

if __name__ == "__main__":
    test_file = "test.mp4"
    test_standard_hash = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"
    test_calculated_hash = calculate_hash_chain_root(test_file)
    
    print("===== test.mp4 验证 =====")
    print(f"官方标准值：{test_standard_hash}")
    print(f"代码计算值：{test_calculated_hash}")
    print(f"验证结果：{'✅ 正确' if test_calculated_hash == test_standard_hash else '❌ 错误'}\n")

    intro_file = "intro.mp4"
    intro_calculated_hash = calculate_hash_chain_root(intro_file)
    print("===== intro.mp4 结果 =====")
    print(f"根哈希值h0：{intro_calculated_hash}")