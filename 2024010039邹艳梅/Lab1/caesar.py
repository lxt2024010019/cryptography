c = "NUFECMWBYUJMBIQGYNBYWIXY"

def decrypt(c, k):
    return ''.join(chr((ord(i)-65-k)%26+65) for i in c)

# 输出所有结果
for k in range(1,26):
    print(f"k={k}: {decrypt(c,k)}")

# 自动识别正确结果
for k in range(1,26):
    p = decrypt(c,k)
    if "TALK" in p:
        print(f"\n✅ 正确密钥：k={k}\n✅ 明文：{p}")
        break