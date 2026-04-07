ciphertext = "NUFECMWBYUJMBIQGYNBYWIXY"

def caesar_decrypt(ciphertext, k):
    """凯撒解密：将每个字母左移k位（模26循环）"""
    plain = ""
    for ch in ciphertext:
        if ch.isalpha() and ch.isupper():
            shifted = (ord(ch) - ord('A') - k) % 26
            plain += chr(shifted + ord('A'))
        else:
            plain += ch
    return plain

def score_english(text):
    """给文本打分，英文常见片段越多得分越高"""
    common_parts = {"THE", "AND", "YOU", "ME", "IS", "TALK", "SHOW", "CODE", "CHEAP"}
    score = 0
    # 检查所有可能的3-4字母片段
    for i in range(len(text)-2):
        triplet = text[i:i+3]
        if triplet in common_parts:
            score += 3
    for i in range(len(text)-3):
        quad = text[i:i+4]
        if quad in common_parts:
            score += 4
    return score

# 暴力枚举所有密钥并打分
best_k = None
best_score = -1
best_plain = ""

print("所有解密结果：")
print("-" * 40)
for k in range(1, 26):
    res = caesar_decrypt(ciphertext, k)
    current_score = score_english(res)
    print(f"k={k:2d}: {res} (得分: {current_score})")
    if current_score > best_score:
        best_score = current_score
        best_k = k
        best_plain = res
print("-" * 40)

# 输出最优结果
print("\n 自动识别结果：")
print(f"最可能的密钥 k = {best_k}")
print(f"对应明文：{best_plain}")