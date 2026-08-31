package wop

// 变异强化第三批：针对第二轮存活 LCR 协议字符串/常量变异
// （hex 表项、Family 常量、TrimAll 双空格折叠、Error 输出契约、
// BaseURL 尾斜杠归一、回调空 path、空入参文案锚点）。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// spec:F2 LCR encoding.go:87-102 —— URLEncodeJava 全 256 字节值穷举，
// 每个表项都是协议行为（Java URLEncoder 语义 + %20 钉子）。
func TestURLEncodeJava_FullByteTable(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := byte(i)
		got := URLEncodeJava(string([]byte{c}))
		var want string
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			c == '.', c == '-', c == '*', c == '_':
			want = string([]byte{c})
		default:
			want = "%" + strings.ToUpper(fmt.Sprintf("%02x", c))
		}
		if got != want {
			t.Errorf("URLEncodeJava(0x%02X) = %q, want %q", c, got, want)
		}
	}
	// 多字节 UTF-8 按字节 %XX（F2 Java-URLEncoder 语义钉子）
	if got := URLEncodeJava("中"); got != "%E4%B8%AD" {
		t.Errorf("UTF-8 编码 = %q, want %%E4%%B8%%AD", got)
	}
	if got := URLEncodeJava("a b"); got != "a%20b" {
		t.Errorf("空格 = %q, want a%%20b", got)
	}
}

// spec:F2 LCR encoding.go:41 —— 连续空白（含双空格）折叠为单空格。
func TestTrimAll_CollapsesRepeatedWhitespace(t *testing.T) {
	cases := map[string]string{
		"a  b":       "a b",
		"a \t b":     "a b",
		"a\n\nb":     "a b",
		"  a  b  ":   "a b",
		"a\x0B\fb\r": "a b",
	}
	for in, want := range cases {
		if got := TrimAll(in); got != want {
			t.Errorf("TrimAll(%q) = %q, want %q", in, got, want)
		}
	}
}

// LCR errors.go:55 —— Error 输出格式是商户可编程契约（code 可解析）。
func TestError_StringFormatContract(t *testing.T) {
	e := &Error{Code: CodeConfiguration, Message: "密钥材料为空"}
	if got := e.Error(); got != "wop: [configuration] 密钥材料为空" {
		t.Errorf("Error() = %q", got)
	}
}

// LCR keys.go:23 / signheader.go:31 / suite.go:60 —— 空入参的文案锚点
// （可诊断性：商户排查依赖关键词，非任意字符串）。
func TestEmptyInput_DiagnosticKeywords(t *testing.T) {
	if _, err := parseSM2PrivateKey(""); err == nil || !strings.Contains(err.Error(), "为空") {
		t.Errorf("空密钥文案 = %v", err)
	}
	if _, err := ParseSignHeader(""); err == nil || !strings.Contains(err.Error(), "缺少") {
		t.Errorf("空签名头文案 = %v", err)
	}
	if _, err := ParseSuite(""); err == nil || !strings.Contains(err.Error(), "为空") {
		t.Errorf("空套件文案 = %v", err)
	}
}

// LCR suite.go:9/10 —— Family 常量对外值（序列化/日志兼容契约）。
func TestSuite_FamilyConstantValues(t *testing.T) {
	if FamilyRSA != "RSA" || FamilySM2 != "SM2" {
		t.Errorf("Family 常量漂移: %q %q", FamilyRSA, FamilySM2)
	}
	s, err := ParseSuite("WOP-SM2-SM3")
	if err != nil || s.Family() != "SM2" {
		t.Errorf("SM2 套件 Family = %v, err=%v", s.Family(), err)
	}
}

// LCR client.go:82 —— GatewayBaseURL 尾斜杠必须归一（否则 path 拼接双斜杠）。
func TestNewClient_TrailingSlashBaseURLNormalized(t *testing.T) {
	var gotTarget string
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.GatewayBaseURL = "https://gw.example.com/"
	cfg.Transport = TransportFunc(func(d RequestDraft) (TransportResponse, error) {
		gotTarget = d.Path // 模拟网关观察到的请求 URI
		return TransportResponse{}, fmt.Errorf("stop")
	})
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = c.Do("GET", "/v1/orders", nil, Level0)
	if gotTarget != "/v1/orders" {
		t.Errorf("path 透传 = %q", gotTarget)
	}
	if c.baseURL != "https://gw.example.com" {
		t.Errorf("baseURL 尾斜杠未归一: %q", c.baseURL)
	}
}

// LCR verify.go:37 —— 回调 URL 无 path 必须拒绝（PROTOCOL）。
func TestVerifyCallback_EmptyPathRejected(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	res := c.VerifyCallback("https://example.com", http.Header{}, nil)
	if res.OK || res.Code != CodeParse {
		t.Errorf("无 path 回调应 parse 拒绝: ok=%v code=%s", res.OK, res.Code)
	}
}
