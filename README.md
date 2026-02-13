# E2E Message

一个基于命令行的端到端加密通信工具。双方通过交换公钥建立安全通道，使用 ECDH 密钥交换和 AES-256-GCM 加密算法，支持前向保密。

## 安装

### 从 Release 下载

前往 [GitHub Releases](https://github.com/user/e2e-message/releases) 下载对应平台的预编译二进制文件。支持 Linux、macOS、Windows 的多种架构。

### 从源码构建

需要 Go 1.21 或更高版本。

```bash
git clone <repo-url>
cd e2e-message
go build -o e2e-message
```

## 快速开始

### 1. 启动程序

双方各自启动程序：

```
./e2e-message
```

启动后会显示你的公钥：

```
=== E2E Message - End-to-End Encryption Tool ===

Your public key (share this with your peer):
BPx7kG...（Base64 编码的公钥）
```

### 2. 交换公钥

将你的公钥通过任意渠道（聊天、邮件等）发送给对方。

### 3. 导入对方公钥

使用 `key` 命令导入对方的公钥：

```
> key BQx8mH...（对方的公钥）
Peer public key imported successfully!
Secure channel established. You can now encrypt and decrypt messages.

=== Security Verification ===
Verify these words match on both sides to ensure no MITM attack:
  apple - dragon - forest - mirror - ocean
```

双方需要确认显示的验证词完全一致，以排除中间人攻击。

### 4. 发送加密消息

使用 `e` 命令加密消息：

```
> e 你好，这是一条加密消息
0 SGVsbG8gV29ybGQ...（加密后的密文）
```

将输出的整行内容（数字和密文）发送给对方。

### 5. 接收并解密消息

收到对方发来的密文后，直接粘贴即可自动解密：

```
> 0 SGVsbG8gV29ybGQ...
你好，这是一条加密消息
```

也可以使用 `d` 命令显式解密：

```
> d 0 SGVsbG8gV29ybGQ...
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `key <公钥>` | 导入对方公钥，建立安全通道 |
| `e <明文>` | 加密消息 |
| `d <序号> <密文>` | 解密消息 |
| `<序号> <密文>` | 自动解密（输入以数字开头时触发） |
| `status` | 查看当前会话状态、消息计数和验证词 |
| `help` | 显示帮助信息 |
| `quit` / `exit` / `q` | 退出程序 |

## 使用说明

### 提示符

提示符会显示最近收到的消息序号：

```
[#3] >
```

这表示最近解密的消息序号为 3。

### 消息格式

加密后的输出格式为 `序号 密文`，例如：

```
0 base64encodedciphertext...
1 anotherbase64ciphertext...
2 yetanotherbase64ciphertext...
```

序号从 0 开始递增。解密时需要提供完整的序号和密文。

### 前向保密

每条消息使用独立的密钥加密。即使某条消息的密钥泄露，也不会影响其他消息的安全性。工具支持乱序接收消息，最多可以容忍 100 条跳跃消息。

### 验证词

建立安全通道后，双方会看到 5 个验证词。请通过电话或其他可信渠道确认双方的验证词完全一致。如果不一致，说明通信可能遭受了中间人攻击，应立即终止会话。

### 快捷操作

- 支持上下方向键浏览命令历史
- 按两次 Ctrl+C 强制退出

## 典型使用流程

```
Alice                                    Bob
─────                                    ───
启动程序，得到公钥 A                       启动程序，得到公钥 B
        ──── 公钥 A ────>
        <──── 公钥 B ────
key <公钥B>                               key <公钥A>
确认验证词一致                             确认验证词一致
e 你好
        ──── 0 密文 ────>
                                          粘贴 "0 密文" 解密
                                          e 收到了
        <──── 0 密文 ────
粘贴 "0 密文" 解密
```

## 技术细节

- 密钥交换：ECDH (P-256)
- 对称加密：AES-256-GCM
- 密钥派生：HKDF-SHA256
- 前向保密：基于 HKDF 的棘轮机制
- 验证词：从共享密钥的 SHA256 哈希中提取

## 运行测试

```bash
go test -v
```

## 许可证

GNU General Public License v3.0
