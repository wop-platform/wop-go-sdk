# WOP Go SDK
[![Go Reference](https://pkg.go.dev/badge/github.com/wop-platform/wop-go-sdk.svg)](https://pkg.go.dev/github.com/wop-platform/wop-go-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/wop-platform/wop-go-sdk)](https://goreportcard.com/report/github.com/wop-platform/wop-go-sdk)
[![CI](https://github.com/wop-platform/wop-go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/wop-platform/wop-go-sdk/actions/workflows/ci.yml)
[![Mutation Gate](https://github.com/wop-platform/wop-go-sdk/actions/workflows/mutation.yml/badge.svg)](https://github.com/wop-platform/wop-go-sdk/actions/workflows/mutation.yml)
[![Release](https://img.shields.io/github/v/release/wop-platform/wop-go-sdk)](https://github.com/wop-platform/wop-go-sdk/releases)
[![License: MIT](https://img.shields.io/github/license/wop-platform/wop-go-sdk)](LICENSE)

[![Go 1.27+](https://img.shields.io/badge/go-1.27%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Coverage](https://img.shields.io/badge/coverage-99.1%25-brightgreen)](https://github.com/wop-platform/wop-go-sdk/actions/workflows/ci.yml)
[![Mutation Kill](https://img.shields.io/badge/mutation_kill-84.9%25%20(%E5%8F%A3%E5%BE%84B)-blueviolet)](https://github.com/wop-platform/wop-specs/pull/5)
[![Gherkin](https://img.shields.io/badge/bdd-18%20scenarios-orange)](features/wop_gateway.feature)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-go-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-go-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

WOP 网关商户侧官方 Go 客户端库：封装协议核心（套件解析、canonicalRequest、结构化签名、
content-digest、L2 数字信封、验签解密）与 HTTP 适配层，商户无需理解线上字节格式即可安全对接。

- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）
- 三套件全支持：`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256`（crypto/rsa）与 `WOP-SM2-SM3`（emmansun/gmsm）
- 零非白名单依赖：运行时依赖仅 [emmansun/gmsm](https://github.com/emmansun/gmsm)（国密算法唯一指定路径，勿用 tjfoc/gmsm——无 GCM）

## 快速开始

```go
package main

import (
	"fmt"

	wop "github.com/wop-platform/wop-go-sdk"
)

func main() {
	client, err := wop.NewClient(wop.Config{
		AppKey:             "app_test_001",
		SecurityReq:        "WOP-RSA3072-SHA256", // 或 WOP-RSA4096-SHA256 / WOP-SM2-SM3
		MerchantPrivateKey: merchantPrivateKeyPEM,
		PlatformPublicKey:  platformPublicKeyPEM,
		GatewayBaseURL:     "https://wop.example.com",
	})
	if err != nil {
		panic(err) // 配置类错误，语义明确，可直接用于接入自查
	}

	// 一站式：L2 加密 + 签名 → 发送 → F6 校验（验签→digest→DEK 解包→alg 族比对→解密）
	result, resp, err := client.Do("POST", "/gateway/logistics.order.query",
		[]byte(`{"waybillNo":"W202607200001"}`), wop.Level2)
	if err != nil {
		if we, ok := err.(*wop.Error); ok {
			fmt.Println("错误码:", we.Code) // 可编程处理；验签/解密类错误对外模糊（I7）
		}
		return
	}
	fmt.Println("HTTP", resp.StatusCode, "明文:", string(result.Plaintext))
}
```

自带 HTTP 栈时直接消费 `RequestDraft`（纯函数产出，零网络 IO）：

```go
draft, err := client.BuildRequest("POST", "/gateway/secure.api", body, wop.Level2)
// draft.Headers / draft.WireBody 交给任意 HTTP 客户端发送
```

回调校验（平台 → 商户，canonical URI 取回调 path）：

```go
res := client.VerifyCallback(callbackURL, http.Header(req.Header), body)
if !res.OK {
	log.Printf("回调校验失败: [%s] %s", res.Code, res.Reason)
	return
}
handle(res.Plaintext)
```

## 密钥准备（D12 分发契约）

| 密钥 | 格式 | 说明 |
|---|---|---|
| RSA 商户私钥 | PKCS#8 DER，PEM 或 Base64 单行 | 位数须与套件一致（3072/4096），不符报配置类错误 |
| RSA 平台公钥 | X.509 SPKI DER，PEM 或 Base64 单行 | 平台下发格式 |
| SM2 商户私钥 | 32 字节大端标量 d，Base64 | `04‖X‖Y` 对应公钥由 d·G 派生校验 |
| SM2 平台公钥 | 未压缩点 `04‖X‖Y`（65 字节），Base64 | 解析时校验在 sm2p256v1 曲线上 |

密钥入参一律为字符串（PEM 块或 Base64 单行，容忍折行）；解析失败全部返回配置类
`wop.Error`（明确指出问题），帮助商户自查。RSA 公钥分发统一 SPKI；SM2 线上格式三钉：
签名裸 `r‖s` 64 字节、密文 `C1C3C2` 裸拼接、禁 ASN.1/DER。

## L0 / L2 示例

```go
// L0 明文：仅签名 + content-digest（无 body 时 digest 头缺席，D2）
draft, _ := client.BuildRequest("POST", "/gateway/open.api", body, wop.Level0)

// L2 全文数字信封：
//   CSPRNG CEK(32B AES / 16B SM4) + IV(12B) → GCM 加密 → {"encrypted":"<b64url>"} 信封
//   DEK 载荷 alg$key$iv 经平台公钥包装（RSA-OAEP 双 SHA-256+空 label / SM2）→ x-wop-encrypt: L2;dek=...
//   content-digest 覆盖密文载体（摘要对象 = 线上原始字节）
draft, _ = client.BuildRequest("POST", "/gateway/secure.api", body, wop.Level2)
```

可测试性钩子：`WithTimestamp` / `WithNonce` / `WithRandom` 注入确定性随机源后
`BuildRequest` 同输入字节级一致（幂等重放断言）；生产环境请勿固定随机源——
GCM 同密钥下 IV 复用即协议不变式 I4 违规。

## 向量自测（conformance）

黄金向量 fixture `internal/testdata/crypto-vectors.json` 是协议真源的字节副本（禁手改），
本地与 CI 消费同一副本：

```bash
go test ./... -covermode=atomic -coverprofile=cover.out -coverpkg=.   # 全量测试（含向量 conformance）
go tool cover -func=cover.out | grep total                # 语句覆盖率 ≥98%（当前 99.1%）
```

覆盖面（spec 附录 B.2 / D9）：

- 正向量字节级：SHA-256/SM3 摘要、RSA3072/4096 签名（PKCS#1 v1.5 确定性）、
  SM2 fixed-k 签名（裸 r‖s）与加密（C1C3C2）、AES-256-GCM / SM4-GCM（ciphertext‖tag）、
  OAEP 解包、DEK 载荷组装
- 负向量全拒：MGF1-SHA1 陷阱密文（F2 头号跨语言漂移源）、C1C2C3 旧国标顺序、
  63/65 字节签名、DER 签名、带 `=` 的 base64url、跨族 digest 标签/securityReq、
  篡改签名/密文/摘要
- 不变式矩阵：`invariants_test.go` 以 `spec:<ID>` 注释索引逐条对账
  （D2/I1/I2/I3/I5/I7/F2/F7/D9），Go 无原生分支计数，以显式负向量清单替代（spec §3 约定）

## 错误处理与模糊化（I7）

| Code | 分类 | 对外语义 |
|---|---|---|
| `CONFIG` / `SUITE_PARSE` / `SUITE_UNSUPPORTED` / `PROTOCOL` | 配置/解析/支持/协议 | **明确**指出问题（鉴权前可判定的公开协议知识） |
| `DIGEST_MISMATCH` | 完整性 | 明确"摘要不匹配" |
| `VERIFY_FAILED` | 验签 | **模糊**："签名验证失败"（固定文案，无细节） |
| `DECRYPT_FAILED` | 解密 | **模糊**："解密失败"（不区分 tag 失败/密钥不符，防 oracle） |
| `ALG_MISMATCH` | 一致性 | 明确（公开映射知识，I3 允许提前拒） |

## Transport

```go
// 默认 net/http 适配器
wop.DefaultTransport{HTTPClient: http.DefaultClient, BaseURL: "https://wop.example.com"}

// 桥接自带 http.RoundTripper（连接池/中间件复用）
tr := wop.RoundTripperTransport(myRoundTripper, baseURL)

// 函数适配（测试 mock）
tr := wop.TransportFunc(func(d wop.RequestDraft) (wop.TransportResponse, error) { ... })
```

## License

MIT
