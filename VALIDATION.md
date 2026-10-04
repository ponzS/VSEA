# VSEA validation record

Date: 2026-10-05. Run ID: `vsea-20261005-3SFVnW`.

验证摘要：macOS arm64 原生构建、独立目录调用、99 次真实 unsea 双向互通操作和 CLI 输入检查通过。未执行设备、浏览器或服务 API 验收。

## Environment and results

- macOS 27.0 arm64; V 0.5.2 (`7647ce1`) with matching tagged standard-library source; OpenSSL 3.6.3; ICU 78.3; Node.js 24.18.1.
- Native example and CLI built from the working tree and an isolated copy containing no other Mox modules. External V application import also passed.
- **99 CLI operations passed** against the actual npm `unsea@1.1.2` implementation: bidirectional signing, encryption and JWK exchange; Chinese, emoji, decomposed accents, Hangul, whitespace/BOM, empty text, embedded NUL and 64 KiB text.
- Invalid signatures/scalars/points/encodings, wrong keys, modified ciphertext/IV/messages, short IV/tag and inconsistent JWK coordinates were rejected. Twenty additional random identities produced signatures accepted by unsea; upstream high-S signatures were accepted by VSEA.
- CLI help/usage and ten malformed/type-invalid JSON inputs passed without parser panics or echoing the input. The multiline `jq` example printed the expected message.
- `v fmt -verify` and whitespace checks passed. These are implementation checks, not formal Mox AC execution or an independent security audit. Linux and Windows were not run.
- Upstream npm tarball SHA-256: `ab9cfde1393ac49d834d33883af0b6308d8818fc9533e2a8f89a7442b678f778`.

## Source snapshot (SHA-256)

```text
91c3d24b8f26e12906923ca5dfb22dada53437740c3fb4e74319e2461926e9a9  backend.c.v
b06a7a30a2ea8f7bffbd66091b6f3b30c84ff6f954aa317337e3de156ac8f017  encoding.v
836d49ee5c30b5d650bc5e3f9224a16d0f881aa3c22c85057336a63f2bbdee12  vsea.v
a7639621215fd5b645eed9e10378f153d8f16eb2b2d21cf6a9f19428ded0f1d5  cmd/cli/main.v
1f2a897b03d6b33973747dc3d5f4fb7649eb287de5add5e7bfc9987f6c3ff9bf  examples/basic.v
a6be0b382af9c364377cc91b85a9203504d3722658a85e84b5f10f88ba9ccc94  v.mod
```

Validated CLI SHA-256: `7230838c8a35fdf543e3029309d9acf21dd5eb276685b3209d1d5d4918cd7fb2`.

## Evidence and cleanup

This record retains the environment, coverage, outcomes and hashes. The run-owned temporary compiler/source downloads, npm package, interoperability driver, isolated copies, binaries and temporary inputs are removed after verification. No permanent test scripts or private keys are included in this repository. No Simulator, database, service, listening port or certificate was created; existing developer toolchains and shared caches are left intact.
