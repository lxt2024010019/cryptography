
## 一、选择题 / 填空题（第 1~19 题）
1. 先压缩，再加密
2. $G'(k) = G(k \oplus 1^s)$、$G'(k) = G(k)[0, \ldots, n-2]$、$G'(k) = G(k) \oplus 1^n$
3. 0.25
4. $p_1 = (k_1,\, k_2),\quad p_2 = (k_1',\, k_2),\quad p_3 = (k_2')$
5. 是的
6. $\mathrm{reverse}(E(k, m))$、$0 \| E(k, m)$
7. 6c73d5240a948c86981bc2808548
8. 9、6、20、19
9. $\log_2 n$
10. 4、6、11、17、19、28
11. $|\mathcal{K}| = 26!$（26 的阶乘）
12. E
13. 1101101
14. 任何随机变量与独立的均匀随机变量异或后，结果仍是均匀分布
15. 能，密钥是 $k = m \oplus c$
16. 1
17. 不能，因为密钥比消息短
18. 是的，给定前 $(n-1)$ 个比特我可以预测第 $n$ 个比特
19. 是

---

## 二、证明题 / 问答题（第 20~24 题）
### 第 20 题 PRG 优势（Advantage）的定义与计算
#### (a) PRG 优势定义式
$$
\mathrm{Adv}_{\mathrm{PRG}}[A, G] = \left| \underset{k \xleftarrow{R} K}{\Pr}[A(G(k))=1] - \underset{r \xleftarrow{R} \{0,1\}^n}{\Pr}[A(r)=1] \right|
$$

#### (b) 优势含义
- 优势接近 1：攻击者可有效区分 PRG 输出与真随机数，PRG 不安全
- 优势接近 0：攻击者无法区分，PRG 安全

#### (c) 计算结果
$\boldsymbol{0}$

---

### 第 21 题 PRG 优势的具体计算
#### (a)
$$
\underset{k \xleftarrow{R} K}{\Pr}[A(G(k)) = 1] = \boldsymbol{\dfrac{2}{3}}
$$

#### (b)
$$
\underset{r \xleftarrow{R} \{0,1\}^n}{\Pr}[A(r) = 1] = \boldsymbol{\dfrac{1}{2}}
$$

#### (c)
$$
\mathrm{Adv}_{\mathrm{PRG}}[A, G] = \left| \dfrac{2}{3} - \dfrac{1}{2} \right| = \boldsymbol{\dfrac{1}{6} \approx 0.1667}
$$

#### (d)
该 PRG 不安全。PRG 安全要求优势可忽略，本题优势为 $\dfrac{1}{6}$，攻击者可通过最高有效位区分 PRG 输出与真随机数。

---

### 第 22 题 证明 OTP 具有完美保密性
#### (a) 完美保密性定义
对任意明文 $m_0,m_1 \in \mathcal{M}$，任意密文 $c \in \mathcal{C}$，满足：
$$
\underset{k \xleftarrow{R} K}{\Pr}[E(k,m_0)=c] = \underset{k \xleftarrow{R} K}{\Pr}[E(k,m_1)=c]
$$

#### (b) 满足 $E(k,m)=c$ 的密钥数量
恰好存在 **1 个** 密钥，$k = m \oplus c$。

#### (c) 证明
对任意 $m_0,m_1,c$，满足 $E(k,m_0)=c$ 与 $E(k,m_1)=c$ 的密钥数均为 1，密钥均匀随机选取，因此：
$$
\underset{k}{\Pr}[E(k,m_0)=c] = \dfrac{1}{|K|} = \underset{k}{\Pr}[E(k,m_1)=c]
$$
满足完美保密性定义，故 OTP 具有完美保密性。

---

### 第 23 题 语义安全性与明文信息泄露
#### (a) 证明
语义安全要求密文不泄露明文任何有效信息。题设存在算法 $A$ 可从密文推出明文最低有效位 $\text{LSB}(m)$，密文泄露明文信息，违背语义安全定义，因此该加密方案不是语义安全的。

#### (b) 构造攻击者 $B$
- 选择消息：$m_0=0^n$，$m_1=1^n$
- 猜测策略：调用 $A$ 得到 $\text{LSB}(m_b)$，直接作为对 $b$ 的猜测

#### (c) 语义安全优势
$$
\mathrm{Adv}_{\mathrm{SS}}[B, \mathbb{E}] = \boldsymbol{1}
$$

---

### 第 24 题 证明 OTP 是语义安全的
#### (a) EXP(0) 密文均匀分布
$k$ 是 $\{0,1\}^n$ 上独立均匀的随机变量，$m_0$ 固定，由异或均匀化性质，$c = k \oplus m_0$ 在 $\{0,1\}^n$ 上均匀分布。

#### (b) EXP(1) 密文均匀分布
同理，$k$ 独立均匀，$m_1$ 固定，$c = k \oplus m_1$ 在 $\{0,1\}^n$ 上均匀分布。

#### (c) 两实验密文分布相同
EXP(0) 与 EXP(1) 的密文均为 $\{0,1\}^n$ 上的均匀分布，二者分布完全相同。

#### (d) OTP 语义安全优势为 0
因两实验密文分布相同，对任意攻击者 $A$：
$$
\underset{k}{\Pr}[A(k \oplus m_0)=1] = \underset{k}{\Pr}[A(k \oplus m_1)=1]
$$
故：
$$
\mathrm{Adv}_{\mathrm{SS}}[A, \mathrm{OTP}] = \left| \Pr[A(k \oplus m_0) = 1] - \Pr[A(k \oplus m_1) = 1] \right| = \boldsymbol{0}
$$
OTP 是语义安全的。

---
