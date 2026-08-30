# WOP Go SDK
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-go-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-go-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

The official Go client library for the WOP gateway (merchant side). It encapsulates the
protocol core (suite parsing, canonicalRequest, structured signing, content-digest,
L2 digital envelope, verify-and-decrypt) plus a pluggable HTTP layer, so merchants
integrate without touching the wire formats.

- Protocol sources of truth: `crypto-strategy-spec.md` (v0.3-reviewed) + `wop-sdk-spec.md` (v1.0-ratified)
- All three suites: `WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` (crypto/rsa) and
  `WOP-SM2-SM3` (emmansun/gmsm)
- Zero non-whitelisted dependencies: the only runtime dependency is
  [emmansun/gmsm](https://github.com/emmansun/gmsm) (the designated SM library — do NOT use
  tjfoc/gmsm, it lacks GCM)

## Quick Start

```go
package main

import (
	"fmt"

	wop "github.com/wop-platform/wop-go-sdk"
)

func main() {
	client, err := wop.NewClient(wop.Config{
		AppKey:             "app_test_001",
		SecurityReq:        "WOP-RSA3072-SHA256", // or WOP-RSA4096-SHA256 / WOP-SM2-SM3
		MerchantPrivateKey: merchantPrivateKeyPEM,
		PlatformPublicKey:  platformPublicKeyPEM,
		GatewayBaseURL:     "https://wop.example.com",
	})
	if err != nil {
		panic(err) // config errors are explicit, safe for integration self-checks
	}

	// One call: L2 encrypt + sign → send → F6 verification
	// (verify → digest recheck → DEK unwrap → alg family check → bulk decrypt)
	result, resp, err := client.Do("POST", "/gateway/logistics.order.query",
		[]byte(`{"waybillNo":"W202607200001"}`), wop.Level2)
	if err != nil {
		if we, ok := err.(*wop.Error); ok {
			fmt.Println("code:", we.Code) // programmable; verify/decrypt errors are fuzzy (I7)
		}
		return
	}
	fmt.Println("HTTP", resp.StatusCode, "plaintext:", string(result.Plaintext))
}
```

Bringing your own HTTP stack? Consume `RequestDraft` directly (pure functions, zero IO):

```go
draft, err := client.BuildRequest("POST", "/gateway/secure.api", body, wop.Level2)
// send draft.Headers / draft.WireBody with any HTTP client
```

Webhook (callback) verification — the canonical URI is the callback path:

```go
res := client.VerifyCallback(callbackURL, http.Header(req.Header), body)
if !res.OK {
	log.Printf("callback rejected: [%s] %s", res.Code, res.Reason)
	return
}
handle(res.Plaintext)
```

## Key Preparation (D12 distribution contract)

| Key | Format | Notes |
|---|---|---|
| RSA merchant private | PKCS#8 DER, PEM or single-line Base64 | Bit size must match the suite (3072/4096) |
| RSA platform public | X.509 SPKI DER, PEM or single-line Base64 | Platform-issued format |
| SM2 merchant private | 32-byte big-endian scalar d, Base64 | Public point derived as d·G and cross-checked |
| SM2 platform public | Uncompressed point `04‖X‖Y` (65 bytes), Base64 | On-curve check against sm2p256v1 |

Keys are passed as strings (PEM blocks or Base64, line breaks tolerated); all parse
failures return an explicit `wop.Error` with `CONFIG` code. SM2 wire formats are pinned:
bare `r‖s` 64-byte signatures, `C1C3C2` ciphertext splicing, ASN.1/DER forbidden on the wire.

## L0 / L2 Examples

```go
// L0 plaintext: signing + content-digest only (digest header absent when there is no body, D2)
draft, _ := client.BuildRequest("POST", "/gateway/open.api", body, wop.Level0)

// L2 full envelope:
//   CSPRNG CEK (32B AES / 16B SM4) + IV (12B) → GCM encrypt → {"encrypted":"<b64url>"}
//   DEK payload alg$key$iv wrapped with the platform public key
//   (RSA-OAEP dual SHA-256 + empty label / SM2) → x-wop-encrypt: L2;dek=...
//   content-digest covers the ciphertext carrier (digest object = raw wire bytes)
draft, _ = client.BuildRequest("POST", "/gateway/secure.api", body, wop.Level2)
```

Test hooks: with `WithTimestamp` / `WithNonce` / `WithRandom` injecting a deterministic
random source, `BuildRequest` is byte-for-byte reproducible (idempotent replay assertions).
Never pin randomness in production — reusing a GCM IV under the same key violates
protocol invariant I4.

## Vector Self-Test (Conformance)

The golden vector fixture `internal/testdata/crypto-vectors.json` is a byte-for-byte copy
of the protocol source of truth (never hand-edit); local tests and CI consume the same copy:

```bash
go test ./... -covermode=atomic -coverprofile=cover.out   # full suite incl. vector conformance
go tool cover -func=cover.out | grep total                # statement coverage ≥98% (currently 98.6%)
```

Coverage (spec appendix B.2 / D9):

- Positive vectors, byte-level: SHA-256/SM3 digests, RSA3072/4096 signatures
  (deterministic PKCS#1 v1.5), SM2 fixed-k signature (bare r‖s) and encryption (C1C3C2),
  AES-256-GCM / SM4-GCM (ciphertext‖tag), OAEP unwrap, DEK payload assembly
- Negative vectors, all rejected: MGF1-SHA1 trap ciphertext (the #1 cross-language drift
  source), C1C2C3 legacy splicing, 63/65-byte signatures, DER signatures, base64url with
  `=`, cross-family digest tags / securityReq, tampered signatures/ciphertexts/digests
- Invariant matrix: `invariants_test.go` maps every clause via `spec:<ID>` comment index
  (D2/I1/I2/I3/I5/I7/F2/F7/D9); Go has no native branch counting, so the explicit negative
  checklist substitutes per spec §3

## Error Handling & Fuzziness (I7)

| Code | Class | External semantics |
|---|---|---|
| `CONFIG` / `SUITE_PARSE` / `SUITE_UNSUPPORTED` / `PROTOCOL` | config/parse/support/protocol | **explicit** (public protocol knowledge, pre-auth) |
| `DIGEST_MISMATCH` | integrity | explicit "digest mismatch" |
| `VERIFY_FAILED` | signature | **fuzzy**: fixed message, no detail |
| `DECRYPT_FAILED` | decryption | **fuzzy**: no distinction between tag failure / wrong key (oracle-proof) |
| `ALG_MISMATCH` | consistency | explicit (public mapping knowledge, I3 allows early rejection) |

## Transport

```go
// Default net/http adapter
wop.DefaultTransport{HTTPClient: http.DefaultClient, BaseURL: "https://wop.example.com"}

// Bridge any http.RoundTripper (reuse your connection pool / middleware)
tr := wop.RoundTripperTransport(myRoundTripper, baseURL)

// Function adapter (test mocks)
tr := wop.TransportFunc(func(d wop.RequestDraft) (wop.TransportResponse, error) { ... })
```

## License

MIT
