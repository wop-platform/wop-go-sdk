package wop

import (
	"bytes"
	"net/http"
	"testing"
)

// F3：x-wop-sign 结构 = <securityReq> v1/<expiredSeconds>/<signedHeaders>/<signature>。
func TestSignHeader_BuildParseRoundtrip(t *testing.T) {
	parsed, err := ParseSignHeader(
		"WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-content-digest;x-wop-nonce;x-wop-timestamp/pOVoj1mI5bqY")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if parsed.securityReq != "WOP-RSA3072-SHA256" {
		t.Errorf("securityReq = %q", parsed.securityReq)
	}
	if parsed.protocolVersion != "v1" || parsed.expiredSeconds != 1800 {
		t.Errorf("authString 段: %s/%d", parsed.protocolVersion, parsed.expiredSeconds)
	}
	if parsed.authString() != "v1/1800" {
		t.Errorf("authString = %q", parsed.authString())
	}
	if len(parsed.signedHeaders) != 4 || parsed.signedHeaders[0] != "x-wop-appkey" {
		t.Errorf("signedHeaders = %v", parsed.signedHeaders)
	}
	if parsed.signature != "pOVoj1mI5bqY" {
		t.Errorf("signature = %q", parsed.signature)
	}

	built := buildSignHeader("WOP-RSA3072-SHA256", 1800,
		[]string{"x-wop-appkey", "x-wop-content-digest", "x-wop-nonce", "x-wop-timestamp"}, "pOVoj1mI5bqY")
	if built != "WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-content-digest;x-wop-nonce;x-wop-timestamp/pOVoj1mI5bqY" {
		t.Errorf("build = %q", built)
	}
}

func TestParseSignHeader_Strict(t *testing.T) {
	good := "WOP-SM2-SM3 v1/1800/x-wop-nonce;x-wop-timestamp/Si7Uw5eZm0Kii3Bu"
	reject := map[string]string{
		"缺失":              "",
		"无空格分隔":           "WOP-SM2-SM3",
		"非 v1 版本":         "WOP-SM2-SM3 v2/1800/a;b/Sg",
		"expired 非数":      "WOP-SM2-SM3 v1/x1800/a;b/Sg",
		"expired 零":       "WOP-SM2-SM3 v1/0/a;b/Sg",
		"expired 超上限":     "WOP-SM2-SM3 v1/86401/a;b/Sg",
		"空 signedHeaders": "WOP-SM2-SM3 v1/1800//Sg",
		"空 signature":     "WOP-SM2-SM3 v1/1800/a;b/ ",
		"段数不足":            "WOP-SM2-SM3 v1/1800/a;b",
	}
	for name, header := range reject {
		if _, err := ParseSignHeader(header); err == nil {
			t.Errorf("%s (%q) 应拒绝", name, header)
		} else if we, ok := err.(*Error); !ok || we.Code != CodeProtocol {
			t.Errorf("%s: 错误类 = %v, want CodeProtocol", name, err)
		}
	}
	if _, err := ParseSignHeader(good); err != nil {
		t.Errorf("合法头 %q 不应拒绝: %v", good, err)
	}
	// 首尾空白容忍（与网关 trim 语义一致）
	if _, err := ParseSignHeader("  " + good + "  "); err != nil {
		t.Errorf("trim 后应接受: %v", err)
	}
}

// F5：L2 信封 wire body = {"encrypted":"<b64url>"}；x-wop-encrypt = L2;dek=<b64u>。
func TestEncryptHeaderAndEnvelope(t *testing.T) {
	h := buildEncryptHeader("QUJD")
	if h != "L2;dek=QUJD" {
		t.Errorf("encrypt header = %q", h)
	}
	level, dek, err := parseEncryptHeader("L2;dek=QUJD")
	if err != nil || level != "L2" || dek != "QUJD" {
		t.Fatalf("parse: level=%q dek=%q err=%v", level, dek, err)
	}

	bad := map[string]string{
		"空":     "",
		"缺分号":   "L2dek=QUJD",
		"非 L2":  "L3;dek=QUJD",
		"缺 dek": "L2;",
		"缺值":    "L2;dek=",
		"带空格":   "L2;dek= QUJD",
	}
	for name, s := range bad {
		if _, _, err := parseEncryptHeader(s); err == nil {
			t.Errorf("%s (%q) 应拒绝", name, s)
		} else if we, ok := err.(*Error); !ok || we.Code != CodeProtocol {
			t.Errorf("%s: 错误类 = %v", name, err)
		}
	}

	wire := wrapEncryptedBody(EncodeB64URL([]byte("cipher")))
	if string(wire) != `{"encrypted":"Y2lwaGVy"}` {
		t.Errorf("wire body = %q", wire)
	}
	if _, err := extractEncryptedBody(wire); err != nil {
		t.Fatalf("extract: %v", err)
	}

	// body 信封负分支
	for name, body := range map[string]string{
		"非 JSON": `not-json`,
		"缺字段":    `{}`,
		"字段非串":   `{"encrypted":42}`,
		"空 body": ``,
	} {
		if _, err := extractEncryptedBody([]byte(body)); err == nil {
			t.Errorf("body %s (%q) 应拒绝", name, body)
		}
	}
	// 未知字段容忍（与网关 readTree.get 语义对齐）
	if _, err := extractEncryptedBody([]byte(`{"encrypted":"Y2lwaGVy","extra":1}`)); err != nil {
		t.Errorf("未知字段应容忍: %v", err)
	}
}

// http.Header 大小写不敏感取值验证（验签管线消费）。
func TestHeaderGetCanonical(t *testing.T) {
	h := http.Header{}
	h.Add("X-Wop-Sign", "A")
	if got := headerValue(h, "x-wop-sign"); got != "A" {
		t.Errorf("大小写不敏感取值失败: %q", got)
	}
	if got := headerValue(h, "x-wop-missing"); got != "" {
		t.Errorf("缺失头应返回空串: %q", got)
	}
	_ = bytes.Equal // 保持导入
}
