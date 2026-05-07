# 导入SHA256哈希算法
from Crypto.Hash import SHA256

def calculate_hash_chain(file_path):
    """
    严格按照实验要求实现哈希链根哈希计算
    步骤：二进制读文件 → 转十六进制 → 2048字符分块 → 反转 → 迭代计算哈希
    """
    # 1. 以二进制模式读取文件
    with open(file_path, "rb") as f:
        file_data = f.read()

    # 2. 转换为十六进制字符串
    hex_data = file_data.hex()

    # 3. 按1KB（2048个十六进制字符）分块
    block_list = [hex_data[i:i+2048] for i in range(0, len(hex_data), 2048)]

    # 4. 反转块列表，从最后一个块开始计算
    reversed_blocks = block_list[::-1]

    # 5. 初始化哈希值（实验要求：初始为空字符串）
    current_hash = ""

    # 6. 遍历计算哈希链
    for block in reversed_blocks:
        # 拼接块数据与上一轮哈希
        combined = block + current_hash
        # 转换为二进制字节
        combined_bytes = bytes.fromhex(combined)
        # 计算SHA256哈希
        hash_result = SHA256.new(combined_bytes)
        # 更新哈希值为十六进制格式
        current_hash = hash_result.hexdigest()

    return current_hash

if __name__ == '__main__':
    # 官方标准校验值
    TEST_STANDARD = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"
    
    # 验证test.mp4
    test_hash = calculate_hash_chain("test.mp4")
    print(f"test.mp4 计算结果：{test_hash}")
    print(f"验证结果：{test_hash == TEST_STANDARD}")

    # 计算intro.mp4根哈希
    intro_hash = calculate_hash_chain("intro.mp4")
    print(f"\nintro.mp4 哈希链根哈希 h0：{intro_hash}")