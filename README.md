# VSEA

[中文文档](./README.zh-CN.md)

VSEA is a **V language rewrite of the core cryptographic functionality of [unsea](https://github.com/draeder/unsea)** by Daniel Raeder. It provides P-256 identities, message signatures, public-key encryption, and portable private JWKs. The compatibility reference is the published **unsea 1.1.2** npm package.

This directory is a standalone source library: it has its own `v.mod`, CLI, example, and MIT license, and does not depend on any Mox module. It follows the bilingual README convention used by the independent repositories under `github/`. Unlike those service release repositories, VSEA maintains library source here. The independent source repository is [ponzS/VSEA](https://github.com/ponzS/VSEA). Build instructions use source; no prebuilt release is required.

## Requirements and build

- V **0.5.2** and a working C compiler.
- OpenSSL **3.x** development headers and libraries, used for P-256 and AES-GCM.
- ICU development headers and libraries, used for Unicode NFC normalization.
- `pkg-config` for dependency discovery on Linux. macOS also recognizes the standard Homebrew ICU paths.

Install native dependencies on macOS:

```sh
brew install openssl@3 icu4c pkgconf
```

On Debian/Ubuntu:

```sh
sudo apt-get install build-essential pkg-config libssl-dev libicu-dev
```

Install V using the [official instructions](https://github.com/vlang/v#installing-v-from-source), then run these commands **inside `vsea/`**:

```sh
v run examples/basic.v
mkdir -p bin
v -o bin/vsea cmd/cli
./bin/vsea --help
```

The example prints `Hello, VSEA! 你好！` and confirms a successful signature/encryption round trip. Native execution has been checked on macOS arm64; Linux dependency instructions are provided, but Linux and Windows execution have not been verified.

## Install directly from GitHub

After installing V and the native dependencies above, install the library directly from its GitHub URL:

```sh
v install --git https://github.com/ponzS/VSEA
```

Then use `import vsea` in your V application and run it normally:

```sh
v run main.v
```

No Mox checkout or custom module search path is required for a VPM installation. To work on VSEA itself, clone the repository into a lowercase `vsea` directory:

```sh
git clone https://github.com/ponzS/VSEA.git vsea
cd vsea
v run examples/basic.v
```

## Library usage

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

For an application outside this directory, put `vsea/` in its V module search path. For example, if the library is `/workspace/libs/vsea`, build the application with:

```sh
v -path '/workspace/libs|@vlib|@vmodules' run main.v
```

The entire directory can be maintained in a separate source repository without the rest of Mox. Keep the checkout directory named `vsea` for the direct example/CLI commands above. Do not commit `bin/`, generated private keys, or temporary input files.

## Public API

All names use V's snake_case convention. Fallible operations return V results (`!`); `verify_message` returns `false` for invalid input or verification failure.

| API | Result / purpose |
| --- | --- |
| `generate_random_pair() !Pair` | Independent signing (`pub`, `priv`) and encryption (`epub`, `epriv`) keys |
| `public_key(private_key string) !string` | Derive the public `x.y` key |
| `sign_message(message, private_key) !string` | Base64url ECDSA signature |
| `verify_message(message, signature, pubkey) bool` | Verify a signature |
| `encrypt_message_with_meta(message, recipient_epub) !EncryptedMessageWithMeta` | Encrypt to the recipient's **encryption** public key |
| `decrypt_message_with_meta(payload, receiver_epriv) !string` | Authenticate and decrypt using the encryption private key |
| `export_to_jwk(private_key) !JWK` | Export a complete private P-256 JWK including `x`, `y`, and `d` |
| `import_from_jwk(jwk JWK) !string` | Import unsea's minimal private JWK or a complete matching JWK |
| `normalize_message(message) !string` | Apply NFC and ECMAScript whitespace trimming |

`Pair`, `EncryptedMessageWithMeta`, and `JWK` expose immutable public fields. Private scalars, public points, signature ranges, nonce lengths, and canonical unpadded base64url are validated. A JWK with public coordinates must match its private scalar.

## CLI

The CLI reads one JSON object from stdin and writes one JSON object to stdout. `keygen` requires no input. Errors are written to stderr. Exit codes are `0` for success, `1` for an operation error or invalid signature, and `2` for a usage error.

| Command | Input | Output |
| --- | --- | --- |
| `keygen` | None | `{pub, priv, epub, epriv}` |
| `sign` | `{message, priv}` | `{signature}` |
| `verify` | `{message, signature, pub}` | `{valid}` |
| `encrypt` | `{message, epub}` | `{ciphertext, iv, sender, timestamp}` |
| `decrypt` | `{payload, epriv}` | `{message}` |
| `export-jwk` | `{priv}` | Private JWK |
| `import-jwk` | `{jwk}` | `{priv}` |

A manual round trip, with `jq` installed, can be run in a private temporary directory:

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

Expected output: `{"message":"Hello, VSEA!"}` (JSON spacing may differ). Private keys travel over stdin rather than command arguments. `keygen` and JWK export output private material; callers are responsible for protecting it. The CLI processes whole messages in memory; it is not a streaming file encryptor.

## unsea compatibility and boundaries

- Private keys: 32-byte P-256 scalars, encoded as unpadded base64url. Public keys: `base64url(x).base64url(y)`, with 32-byte coordinates.
- Signatures: SHA-256 of normalized UTF-8 text, then ECDSA P-256; wire format is 64-byte `r || s`. VSEA emits low-S signatures and accepts both valid S forms emitted by unsea. OpenSSL uses randomized signing, so signature bytes need not equal unsea's deterministic output.
- Encryption: fresh ephemeral P-256 key per message; `SHA-256(ECDH shared x-coordinate)` gives the AES-256 key. Each message uses a random 12-byte IV and a 16-byte GCM tag appended to the ciphertext. No additional authenticated data is used.
- Envelopes use `ciphertext`, `iv`, `sender`, and a Unix-millisecond `timestamp`, matching unsea. Pass `recipient.epub` to the V API; JavaScript unsea accepts the recipient object.
- **Signing and encryption both apply NFC normalization and trim leading/trailing ECMAScript whitespace**, matching unsea. They do not preserve the original text byte-for-byte. Decryption returns the authenticated text without normalizing it again.
- `sender` is an ephemeral key, **not proof of the sender's identity**. `timestamp` is informational and unauthenticated. Applications must separately handle identity signatures, freshness and replay policy.
- Inputs are stricter than unsea's permissive parsing: noncanonical base64url, invalid scalars/points and inconsistent JWK coordinates are rejected. Invalid UTF-8 plaintext is rejected instead of being replaced with replacement characters.
- This initial version covers the cryptographic core. Browser IndexedDB key storage, password storage wrappers, PEM conversion, proof of work and signed work are not included. VSEA does not implement Mox-specific mesh signature rules.