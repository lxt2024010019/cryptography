# Lab5 分组密码习题解答
## 第 1 题
[ x ] 2, 3, 4, 1, 5
[   ] 2, 3, 1, 5, 4
[   ] 2, 3, 1, 4, 5

## 第 2 题
[   ] 超过一小时但不到一天
[   ] 超过一周但不到一个月
[   ] 超过一个月但不到一年
[   ] 超过一年但不到 100 年
[ x ] 超过 10^9（十亿）年

## 第 3 题
[   ] F'(k, x) = F(k, x) | 0
[ x ] F'((k1,k2),x) = F(k1,x) | F(k2,x)
[   ] F'(k, x) = F(k, x) | F(k, x)
[ x ] F'(k, x) = reverse(F(k, x))
[   ] F'(k, x) = F(k, x) (x≠0^n), 0^n (x=0^n)
[   ] F'(k, x) = F(k, x) (x≠0^n), k (x=0^n)
[   ] F'(k, x) = F(k, x)[0,…,n-2]

## 第 4 题
[ x ] 输入 0^64 时输出为 5f67abaf5210722b；输入 1^320^32 时输出为 bbe033c00bc9330e
[   ] 输入 0^64 时输出为 4af532671351e2e1；输入 1^320^32 时输出为 87a40cfa8dd39154
[   ] 输入 0^64 时输出为 2d1cfa42c0b1d266；输入 1^320^32 时输出为 eea6e3ddb2146dd0
[   ] 输入 0^64 时输出为 9f970f4e932330e4；输入 1^320^32 时输出为 6068f0b1b645c008

## 第 5 题
[   ] c1 = c0
[   ] c0 = c1
[ x ] c1 = c0'
[   ] c0 = c0'

## 第 6 题
[   ] 0
[   ] 1
[ x ] 2
[   ] 3
[   ] ℓ/2

## 第 7 题
[   ] 0
[ x ] 1
[   ] 2
[   ] 3
[   ] ℓ/2

## 第 8 题
[   ] 'To consider the resistance of an enciphering process to being broken we should assume that at same times the enemy knows everything but the key being used and to break it needs only discover the key from this information.'
[   ] 'In this letter I make some remarks on a general principle relevant to enciphering in general and my machine.'
[   ] 'We see immediately that one needs little information to begin to break down the process.'
[ x ] 'The most direct computation would be for the enemy to try all 2^r possible keys, one by one.'

## 第 9 题
答案：1111

## 第 10 题
[   ] 双重加密使密文长度翻倍，容易被检测
[ x ] 中间相遇攻击（Meet-in-the-Middle Attack）可将搜索空间降至 2^n，与单次 DES 相同
[   ] 双重加密破坏了 Feistel 网络的结构
[   ] 两次加密可能相互抵消，导致密文等于明文

## 第 11 题
[ x ] 计时攻击（Timing Attack）
[ x ] 功耗分析攻击（Power Analysis Attack）
[ x ] 电磁泄漏攻击（EM Attack）
[   ] 穷举攻击（Brute Force Attack）
[ x ] 缓存攻击（Cache Attack）

## 第 12 题
[   ] 利用加密函数的代数结构直接求解密钥方程
[ x ] 寻找明文位、密文位和密钥位之间的线性近似关系，利用统计偏差恢复密钥
[   ] 通过构造特殊的明文对（差分对）来追踪密钥差异的传播
[   ] 利用量子计算机的并行性加速穷举搜索

## 第 13 题
[   ] 寻找明文、密文和密钥之间的线性关系
[   ] 利用加密时间与密钥位之间的相关性
[ x ] 选择具有特定差分的明文对，分析差分在密码内部如何传播，从而恢复子密钥
[   ] 通过傅里叶变换分析密文的统计特性

## 第 14 题
[   ] Shor 算法可以在多项式时间内破解 AES
[   ] 量子叠加态使得 AES 的密钥空间可以直接遍历
[ x ] Grover 搜索算法可以将穷举搜索的复杂度从 O(2^n) 降低到 O(2^(n/2))
[   ] 量子纠缠可以无限加速 AES 的加密过程
[   ] 量子隧穿效应使得 AES 密钥可以被直接读取

## 第 15 题
[   ] AddRoundKey → SubBytes → ShiftRows → MixColumns
[   ] ShiftRows → MixColumns → SubBytes → AddRoundKey
[   ] MixColumns → AddRoundKey → ShiftRows → SubBytes
[ x ] SubBytes → ShiftRows → MixColumns → AddRoundKey
[   ] AddRoundKey → ShiftRows → MixColumns → SubBytes

## 第 16 题
[   ] 安全的 PRF 一定是安全的 PRP
[   ] 安全的 PRP 一定是安全的 PRF
[ x ] 安全的 PRP 也是安全的 PRF（PRP/PRF 转换引理）：当输出长度为 n 位时，区分 PRP 和 PRF 的最大优势不超过 q²/2ⁿ，其中 q 为查询次数
[   ] PRP 和 PRF 是完全等价的概念，可以互换使用

## 第 17 题
[   ] 不能，PRG 只能生成随机比特，无法构造排列
[ x ] 能，先用 GGM 构造从 PRG 构造 PRF，再用 Luby-Rackoff 定理（三轮 Feistel 网络）从 PRF 构造 PRP
[   ] 取决于具体的 PRG，只有特定 PRG 可以
[   ] 只能构造 PRF，无法进一步构造 PRP

## 第 18 题
[   ] 对于每个密钥 k，E(k, ·) 都不是排列
[   ] E 是一个安全的 PRP
[ x ] 对于每个密钥 k，E(k, ·) 确实是 0,1 上的排列，但 E 不是一个安全的 PRP，因为密钥空间和定义域都太小（只有 2 个元素），攻击者可以轻松区分
[   ] E 不是一个排列，因为不同的密钥可能产生相同的输出

## 第 19 题
[   ] q/2ⁿ
[ x ] q²/2ⁿ（其中 n 为 PRP 的输入/输出位数）
[   ] q/2²ⁿ
[   ] q²/2²ⁿ
[   ] 1/2ⁿ

## 第 20 题
[ x ] ECB 模式是确定性的：相同的明文分组总是产生相同的密文分组，会泄露明文中的重复模式
[   ] ECB 模式无法正确处理长度不是分组大小整数倍的消息
[   ] ECB 模式的加密速度比其他模式慢得多
[   ] ECB 模式需要多个密钥才能工作
[   ] ECB 模式不支持并行解密

## 第 21 题
[ x ] CTR 模式支持加密的完全并行化，CBC 模式的加密过程是串行的（必须依次处理每个分组）
[ x ] CTR 模式支持密文的随机访问解密（可直接解密任意分组），CBC 模式需要从前往后依次解密
[ x ] 在 CTR 模式中，一个密文分组的损坏只会影响对应的明文分组；在 CBC 模式中，一个密文分组的损坏会影响当前和下一个明文分组
[   ] CBC 模式支持流式加密（不需要知道消息总长度），CTR 模式不支持
[ x ] CTR 模式本质上将分组密码转换为流密码使用

## 第 22 题
[   ] 两轮 Feistel 无法实现双向可逆
[ x ] 两轮 Feistel 的左半部分输出等于左半部分输入（不变），攻击者可以据此区分两轮 Feistel 与随机排列
[   ] 两轮 Feistel 会导致输出长度与输入长度不同
[   ] 三轮 Feistel 是确保正确解密所需的最小轮数

## 第 23 题
[ x ] 安全的分组密码应该在不知道密钥的情况下，即使攻击者可以获取任意明文的加密结果（CPA 安全），也无法区分其与真正的随机排列
[ x ] 理想情况下，破解安全的 n 位分组密码的最佳方法是穷举搜索，复杂度为 O(2ⁿ)
[   ] 增加密钥长度总能线性地增加安全性（如双倍密钥长度则安全强度翻倍）
[ x ] 分组密码的安全性不依赖于算法的保密性（Kerckhoffs 原则），而仅依赖于密钥的保密性

## 第 24 题
[   ] C = E_k3(E_k2(E_k1(M)))，有效密钥长度为 168 位
[ x ] C = E_k1(D_k2(E_k3(M)))（EDE 结构），三密钥版本有效安全强度约为 112 位（受中间相遇攻击限制）
[   ] C = D_k1(E_k2(D_k3(M)))，有效密钥长度为 56 位
[   ] C = E_k1(E_k2(M))⊕k3，有效密钥长度为 168 位

## 第 25 题
[   ] C = E_k2(M⊕k1)，通过在加密前异或一个额外密钥来增加密钥长度
[   ] C = E_k1(M)⊕k2，通过在加密后异或一个额外密钥来增加密钥长度
[ x ] C = k3⊕E_k2(M⊕k1)，通过在加密前后各异或一个白化密钥（key whitening）来抵抗穷举攻击，有效密钥长度提升至约 120 位
[   ] C = E_k1(E_k2(M⊕k3))，通过两次加密和一个异或来提升安全性

## 第 26 题
[   ] DES 的 F 函数是可逆的，DES 整体也是可逆的
[   ] DES 的 F 函数是不可逆的，DES 整体也是不可逆的
[   ] DES 的 F 函数是可逆的，但 DES 整体是不可逆的
[ x ] DES 的 F 函数本身不是可逆的（F 函数将 32 位扩展为 48 位后经 S-box 压缩回 32 位，不构成双射），但得益于 Feistel 网络结构，DES 整体是可逆的（解密只需逆序使用各轮子密钥）

## 第 27 题
[ x ] Nonce 在同一密钥下绝对不能重复使用（唯一性）：一旦重复，攻击者可通过两次密文的异或消去密钥流，直接得到两段明文的异或
[   ] Nonce 必须是真随机数，使用计数器或时间戳是不安全的
[ x ] Nonce 不需要保密：Nonce 可以明文附在密文旁边传输，攻击者知道 Nonce 也无法破解密文（前提是密钥保密）
[ x ] Nonce 不要求随机性：只要保证唯一即可，简单递增的计数器就是合法的 Nonce
[   ] Nonce 的长度必须与密钥长度相同

## 第 28 题
[ x ] 随机数来源必须是密码学安全的伪随机数生成器（CSPRNG）：使用 rand()、时间戳等非密码学随机源生成 IV/Nonce 可能导致可预测，破坏语义安全
[ x ] IV/Nonce 的重用会灾难性地破坏安全性：在 CTR 模式下，两次使用相同 Nonce + Key 加密不同明文，攻击者可直接异或两段密文消去密钥流
[ x ] 随机化加密本身不提供完整性和认证保护（仅提供机密性）：攻击者可以任意篡改密文，接收方无法检测，应额外使用 MAC 或 AEAD 模式（如 AES-GCM）
[ x ] 随机化加密中密钥可以重复使用多次，不影响安全性
[ x ] 密文会比明文稍长：需要将 IV 或 Nonce 一并传输给接收方（通常附在密文开头），因此密文长度 = IV/Nonce 长度 + 加密后密文长度