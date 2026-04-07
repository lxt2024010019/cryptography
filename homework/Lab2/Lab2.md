# Lab：多次填充攻击流密码

## 实验背景

流密码通过将明文与密钥流进行 XOR 运算来实现加密。若密钥流由伪随机数生成器（PRG）根据密钥 $k$ 生成，则加密过程为：

$$C = M \oplus \text{PRG}(k)$$

**安全前提：同一密钥绝不能使用两次。**

若攻击者获得两段使用相同密钥加密的密文：

$$C_1 = M_1 \oplus \text{PRG}(k)$$
$$C_2 = M_2 \oplus \text{PRG}(k)$$

则将两段密文异或，密钥流被消除：

$$C_1 \oplus C_2 = M_1 \oplus M_2$$

由此，攻击者无需知道密钥，即可直接对明文异或结果进行分析。

> **提示**：当空格字符（`0x20`）与英文字母（`[a-zA-Z]`）进行 XOR 时，大写字母变为小写，小写字母变为大写。利用这一规律可有效推断明文中的空格位置。

---

## 实验任务

以下是 11 段使用**同一流密码密钥**加密的十六进制密文，你的目标是**解密最后一段目标密文**。

### 密文 #1
```
315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e
```

### 密文 #2
```
234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f
```

### 密文 #3
```
32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb
```

### 密文 #4
```
32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa
```

### 密文 #5
```
3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070
```

### 密文 #6
```
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4
```

### 密文 #7
```
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce
```

### 密文 #8
```
315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3
```

### 密文 #9
```
271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027
```

### 密文 #10
```
466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83
```

### 🎯 目标密文（请解密此段）
```
32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904
```

---

## 实验要求

1. 使用任意编程语言实现（推荐 Python）
2. 核心思路：
   - 将多段密文两两 XOR，消去密钥流，得到明文 XOR 明文
   - 利用**空格与字母 XOR 的规律**推断各位置的明文字符
   - 逐步还原密钥流，最终解密目标密文
3. 在代码注释或实验报告中说明：
   - 你使用了哪种分析方法
   - 如何确认目标密文的明文内容
   - 解密得到的明文是什么

---

## 提交要求

在自己的文件夹下新建 `Lab2/` 目录，提交以下文件：

```
学号姓名/
└── Lab2/
    ├── attack.py       # 源代码
    └── report.md       # 简要说明（方法、密钥流推断过程、最终明文）
```

---

## 截止时间

**2026-3-31**，届时关于 Lab2 的 PR 请求将不会被合并。

---

