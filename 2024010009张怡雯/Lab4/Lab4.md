# Lab4：AES CBC 模式与 CTR 模式加解密实现



## 实验任务

请使用任意编程语言（推荐 Python）实现 AES CBC 模式和 CTR 模式的**加密与解密**。你可以使用现有的加密库（如 PyCrypto）中的 AES 基本功能，但要求**自行实现 CBC 和 CTR 的工作模式逻辑**。

本题仅测试**解密**功能。以下各题给出了 AES 密钥和密文（均为十六进制编码），请解密并恢复出明文。

---

## 第 1 题

**CBC 模式解密**

- **密钥**：`140b41b22a29beb4061bda66b6747e14`
- **密文 1**：

```
4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81
```

**答案：** ___Basic CBC mode encryption needs padding._______

---

## 第 2 题

**CBC 模式解密**

- **密钥**：`140b41b22a29beb4061bda66b6747e14`（与第 1 题相同）
- **密文 2**：

```
5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253
```

**答案：** _____Our implementation uses rand. IV______

---

## 第 3 题

**CTR 模式解密**

- **密钥**：`36f18357be4dbd77f050515c73fcf9f2`
- **密文 1**：

```
69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329
```

**答案：** ___CTR mode lets you build a stream cipher from a block cipher.________

---

## 第 4 题

**CTR 模式解密**

- **密钥**：`36f18357be4dbd77f050515c73fcf9f2`（与第 3 题相同）
- **密文 2**：

```
770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
```

**答案：** ___Always avoid the two time pad!________

---

