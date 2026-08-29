package wop

// 变异强化第五批：密钥解析前置检查的独立价值。跳过前置后下游（x509/gmsm）
// 也会报错，但错误模型不同（库错误 vs *Error）——断言前置检查产 *Error/CONFIG
// 即可钉死每个前置分支（COI keys.go:23/37/45/49/61/65/78/94/97）。

import (
	"encoding/base64"
	"strings"
	"testing"
)

func requireConfigError(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s 应拒绝", what)
		return
	}
	we, ok := err.(*Error)
	if !ok {
		t.Errorf("%s 应为前置 *Error，实际库错误透传 %T: %v", what, err, err)
		return
	}
	if we.Code != CodeConfig {
		t.Errorf("%s 错误码 = %s, want CONFIG", what, we.Code)
	}
}

func TestKeyParsing_PreflightConfigErrors(t *testing.T) {

	// keys.go:23 空密钥材料
	requireConfigError(t, "空密钥材料", func() error {
		_, err := parseRSAPublicKey("")
		return err
	}())
	// keys.go:37 非 Base64 材料
	requireConfigError(t, "非法 Base64", func() error {
		_, err := parseRSAPublicKey("!!not-base64!!")
		return err
	}())
	// keys.go:45/49 SPKI 非 RSA / 畸形 DER（EC 公钥 DER 喂 RSA 解析）
	requireConfigError(t, "非 RSA 公钥 DER", func() error {
		_, err := parseRSAPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" +
			strings.Repeat("A", 80))
		return err
	}())
	// keys.go:61/65 非 PKCS#8 私钥（喂 PKIX 公钥 DER）
	requireConfigError(t, "非 PKCS#8 私钥", func() error {
		_, err := parseRSAPrivateKey("MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK" +
			strings.Repeat("B", 40))
		return err
	}())
	// keys.go:78 SM2 公钥长度/前缀不符（66B、04 开头：跳过 65B 检查后 gmsm 拒）
	requireConfigError(t, "66B 假点", func() error {
		raw := make([]byte, 66)
		raw[0] = 0x04
		_, err := parseSM2PublicKey(base64Of(raw))
		return err
	}())
	// keys.go:94 SM2 私钥长度不符（31B）
	requireConfigError(t, "31B 私钥", func() error {
		raw := make([]byte, 31)
		raw[0] = 0x7F
		_, err := parseSM2PrivateKey(base64Of(raw))
		return err
	}())
	// keys.go:97 非 Base64 私钥材料
	requireConfigError(t, "私钥非法 Base64", func() error {
		_, err := parseSM2PrivateKey("%%%")
		return err
	}())
}

func base64Of(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
