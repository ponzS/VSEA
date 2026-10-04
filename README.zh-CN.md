# VSEA

[English](./README.md)

VSEA 是使用 **V 语言基于 Daniel Raeder 的 [unsea](https://github.com/draeder/unsea) 核心密码功能改写的独立库**，提供 P-256 身份密钥、消息签名、公钥加密和私钥 JWK 交换。兼容性参考版本为 npm 已发布的 **unsea 1.1.2**。

本目录拥有独立的 `v.mod`、命令行工具、示例和 MIT 许可证，不依赖其他 Mox 模块。文档参考 `github/` 下独立仓库的形式，以英文 `README.md` 和中文 `README.zh-CN.md` 相互链接。与服务发布仓库不同，VSEA 在本目录维护库源码；独立源码仓库为 [ponzS/VSEA](https://github.com/ponzS/VSEA)，以下构建方式直接使用源码，无需预编译发布包。

## 环境与构建

- V **0.5.2** 和可用的 C 编译器。
- OpenSSL **3.x** 开发头文件及库，用于 P-256 和 AES-GCM。
- ICU 开发头文件及库，用于 Unicode NFC 规范化。
- Linux 使用 `pkg-config` 查找依赖；macOS 也支持标准 Homebrew ICU 安装路径。

macOS 安装原生依赖：

```sh
brew install openssl@3 icu4c pkgconf
```

Debian/Ubuntu：

```sh
sudo apt-get install build-essential pkg-config libssl-dev libicu-dev
```

按照 [V 官方说明](https://github.com/vlang/v#installing-v-from-source) 安装 V，然后**进入 `vsea/` 目录**执行：

```sh
v run examples/basic.v
mkdir -p bin
v -o bin/vsea cmd/cli
./bin/vsea --help
```

示例输出 `Hello, VSEA! 你好！`，并确认签名、加解密成功。当前已在 macOS arm64 上实际运行；Linux 提供依赖安装说明，Linux 和 Windows 尚未完成运行验证。

## 直接通过 GitHub 安装

安装 V 和上述原生依赖后，可以直接使用 GitHub 地址安装库：

```sh
v install --git https://github.com/ponzS/VSEA
```

随后在自己的 V 程序中使用 `import vsea`，按普通 V 程序运行：

```sh
v run main.v
```

通过 VPM 安装后，无需克隆 Mox，也无需指定额外模块搜索路径。如果需要维护 VSEA 本身，请将仓库克隆到小写的 `vsea` 目录：

```sh
git clone https://github.com/ponzS/VSEA.git vsea
cd vsea
v run examples/basic.v
```

## 作为库使用

```v
import vsea

fn main() {
    alice := vsea.generate_random_pair()!
    bob := vsea.generate_random_pair()!
    message := 'Hello, VSEA! 你好！'

    signature := vsea.sign_message(message, alice.priv)!
    assert vsea.verify_message(message, signature, alice.pub)

    payload := vsea.encrypt_message_with_meta(message, bob.epub)!
    plaintext := vsea.decrypt_message_with_meta(payload, bob.epriv)!
    assert plaintext == message
    println(plaintext)
}
```

其他项目使用时，将 `vsea/` 加入 V 的模块搜索路径。例如库位于 `/workspace/libs/vsea`，可这样运行调用方：

```sh
v -path '/workspace/libs|@vlib|@vmodules' run main.v
```

整个目录可以移入独立源码仓库，不需要携带其他 Mox 目录。使用上述直接运行示例／构建 CLI 的命令时，请保持检出目录名为 `vsea`。不要提交 `bin/`、生成的私钥或临时输入文件。

## 公共 API

函数名采用 V 的 snake_case。可能失败的操作通过 V 的结果类型（`!`）返回错误；`verify_message` 在输入无效或验签失败时返回 `false`。

| API | 返回结果／用途 |
| --- | --- |
| `generate_random_pair() !Pair` | 分别生成签名密钥（`pub`、`priv`）和加密密钥（`epub`、`epriv`） |
| `public_key(private_key string) !string` | 从私钥派生 `x.y` 格式公钥 |
| `sign_message(message, private_key) !string` | 生成 base64url 编码的 ECDSA 签名 |
| `verify_message(message, signature, pubkey) bool` | 验证签名 |
| `encrypt_message_with_meta(message, recipient_epub) !EncryptedMessageWithMeta` | 使用接收方的**加密公钥**加密 |
| `decrypt_message_with_meta(payload, receiver_epriv) !string` | 使用加密私钥认证并解密 |
| `export_to_jwk(private_key) !JWK` | 导出包含 `x`、`y`、`d` 的完整 P-256 私钥 JWK |
| `import_from_jwk(jwk JWK) !string` | 导入 unsea 的最小私钥 JWK 或公私钥一致的完整 JWK |
| `normalize_message(message) !string` | NFC 规范化并去除 ECMAScript 定义的首尾空白 |

`Pair`、`EncryptedMessageWithMeta`、`JWK` 提供不可变的公开字段。库会检查私钥标量、公钥曲线点、签名范围、IV 长度和规范的无填充 base64url。JWK 如果提供公钥坐标，必须与私钥一致。

## 命令行工具

工具从标准输入读取一个 JSON 对象，向标准输出写入一个 JSON 对象。`keygen` 不需要输入；错误写入标准错误。退出码：`0` 表示成功，`1` 表示操作失败或签名无效，`2` 表示命令用法错误。

| 命令 | 输入 | 输出 |
| --- | --- | --- |
| `keygen` | 无 | `{pub, priv, epub, epriv}` |
| `sign` | `{message, priv}` | `{signature}` |
| `verify` | `{message, signature, pub}` | `{valid}` |
| `encrypt` | `{message, epub}` | `{ciphertext, iv, sender, timestamp}` |
| `decrypt` | `{payload, epriv}` | `{message}` |
| `export-jwk` | `{priv}` | 私钥 JWK |
| `import-jwk` | `{jwk}` | `{priv}` |

安装 `jq` 后，可以在私有临时目录中手工验证加解密：

```sh
umask 077
vsea_run=$(mktemp -d)
./bin/vsea keygen > "$vsea_run/keys.json"
jq '{message: "Hello, VSEA!", epub}' "$vsea_run/keys.json" \
  | ./bin/vsea encrypt > "$vsea_run/message.json"
jq -n --slurpfile keys "$vsea_run/keys.json" \
  --slurpfile payload "$vsea_run/message.json" \
  '{epriv: $keys[0].epriv, payload: $payload[0]}' | ./bin/vsea decrypt
rm "$vsea_run/keys.json" "$vsea_run/message.json"
rmdir "$vsea_run"
```

预期输出 `{"message":"Hello, VSEA!"}`，JSON 空格可能不同。私钥通过标准输入传递，不放进命令行参数。`keygen` 和 JWK 导出会输出私密材料，需要调用方妥善保管。命令行工具在内存中处理整条消息，不提供流式文件加密。

## unsea 兼容性与边界

- 私钥：32 字节 P-256 标量，使用无填充 base64url。公钥：`base64url(x).base64url(y)`，两个坐标各 32 字节。
- 签名：对规范化后的 UTF-8 文本计算 SHA-256，再使用 ECDSA P-256；传输格式为 64 字节 `r || s`。VSEA 输出 low-S 签名，验签接受 unsea 产生的两种有效 S 值形式。OpenSSL 使用随机签名，因此签名字节不保证与 unsea 的确定性签名相同。
- 加密：每条消息生成新的临时 P-256 密钥，以 `SHA-256(ECDH 共享点的 x 坐标)` 作为 AES-256 密钥；使用随机 12 字节 IV，密文末尾附加 16 字节 GCM 标签，不使用附加认证数据。
- 密文信封字段为 `ciphertext`、`iv`、`sender` 和 Unix 毫秒时间戳 `timestamp`，与 unsea 一致。V API 接收 `recipient.epub` 字符串，JavaScript unsea 接收接收方对象。
- **签名和加密都会先执行 NFC 规范化，再去除 ECMAScript 定义的首尾空白**，与 unsea 一致，不保证保留原始文本的全部字节。解密直接返回认证通过的文本，不再规范化。
- `sender` 是临时公钥，**不是发送方身份认证**；`timestamp` 仅供参考，不受认证保护。应用需要单独处理身份签名、时效和重放策略。
- 输入校验比 unsea 的宽松解析更严格：拒绝非规范 base64url、无效标量／曲线点，以及公私钥不一致的 JWK。无效 UTF-8 明文会报错，不会自动替换非法字符。
- 首版覆盖核心密码能力，未移植浏览器 IndexedDB 密钥存储、密码存储封装、PEM 转换、工作量证明和签名工作量证明，也不实现 Mox 特有的 Mesh 签名规则。