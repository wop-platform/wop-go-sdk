package wop

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// spec:2.2-1 闭集完整性：七值全等、互异、全小写 ASCII（跨语言恒定，禁止自造）。
func TestErrorCode_ClosedSetValues(t *testing.T) {
	closed := map[ErrorCode]string{
		CodeConfiguration: "configuration",
		CodeParse:         "parse",
		CodeUnsupported:   "unsupported",
		CodeIntegrity:     "integrity",
		CodeConsistency:   "consistency",
		CodeSignature:     "signature",
		CodeDecrypt:       "decrypt",
	}
	if len(closed) != 7 {
		t.Fatalf("闭集必须恰 7 值，实际 %d", len(closed))
	}
	lower := regexp.MustCompile(`^[a-z]+$`)
	seen := map[string]ErrorCode{}
	for code, want := range closed {
		if string(code) != want {
			t.Errorf("常量 %s = %q, want %q", code, code, want)
		}
		if prev, dup := seen[want]; dup {
			t.Errorf("闭集值 %q 被 %s 与 %s 重复使用", want, prev, code)
		}
		seen[want] = code
		if !lower.MatchString(string(code)) {
			t.Errorf("闭集值 %q 必须全小写 ASCII", code)
		}
	}
}

// spec:2.2-2 否定式：生产源码全部错误构造点（newError/fuzzyError/VerifyResult.Code）
// 仅引用闭集七常量；旧名（SUITE_PARSE/VERIFY_FAILED/DIGEST_MISMATCH 等）或任意
// 新自造常量出现即判违规。
func TestErrorCode_SourceOnlyUsesClosedSet(t *testing.T) {
	closedNames := map[string]bool{
		"CodeConfiguration": true, "CodeParse": true, "CodeUnsupported": true,
		"CodeIntegrity": true, "CodeConsistency": true, "CodeSignature": true,
		"CodeDecrypt": true,
	}
	pats := []*regexp.Regexp{
		regexp.MustCompile(`newError\((Code\w+)`),
		regexp.MustCompile(`fuzzyError\((Code\w+)`),
		regexp.MustCompile(`Code:\s*(Code\w+)`),
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, pat := range pats {
			for _, m := range pat.FindAllStringSubmatch(string(src), -1) {
				if !closedNames[m[1]] {
					t.Errorf("%s: 错误构造点引用闭集外常量 %s", name, m[1])
				}
			}
		}
	}
}

// spec:2.2-3 否定式：非法 securityReq 绝不落入 parse/unsupported
// （旧 SUITE_PARSE/SUITE_UNSUPPORTED 分类已并入 configuration，F1）。
func TestErrorCode_NeverClassifiesSuiteErrorsAsParseOrUnsupported(t *testing.T) {
	for _, bad := range []string{"", "RSA3072-SHA256", "WOP-RSA2048-SHA256", "WOP-RSA3072-SM3"} {
		_, err := ParseSuite(bad)
		if err == nil {
			t.Fatalf("ParseSuite(%q) 应拒绝", bad)
		}
		if we := err.(*Error); we.Code == CodeParse || we.Code == CodeUnsupported {
			t.Errorf("ParseSuite(%q) code = %s, 必须归 configuration（F1）", bad, we.Code)
		}
	}
}

// spec:D6-1 明确类（configuration/parse/integrity）错误文案全等钉死：
// 商户可依赖精确文案自查（全等断言，非 contains）。
func TestErrorCode_ExplicitMessagesExact(t *testing.T) {
	// configuration：securityReq 为空（suite.go）
	if _, err := ParseSuite(""); err == nil {
		t.Fatal("空 securityReq 应拒绝")
	} else if we := err.(*Error); we.Message != "securityReq 为空" {
		t.Errorf("configuration 文案 = %q, want %q", we.Message, "securityReq 为空")
	}
	// configuration：三段式格式非法（含原值回显）
	if _, err := ParseSuite("RSA3072-SHA256"); err == nil {
		t.Fatal("非法 securityReq 应拒绝")
	} else if we := err.(*Error); we.Message != `securityReq 格式非法 "RSA3072-SHA256"：应为 WOP-<密钥算法>-<摘要算法> 三段式` {
		t.Errorf("configuration 文案 = %q", we.Message)
	}
	// parse：digest 格式非法（digest.go）
	if _, _, err := ParseContentDigest("garbage"); err == nil {
		t.Fatal("非法 digest 头应拒绝")
	} else if we := err.(*Error); we.Message != "x-wop-content-digest 格式非法：须为 <sha-256|sm3> + 恰一空格 + 64 位小写 hex" {
		t.Errorf("parse 文案 = %q", we.Message)
	}
	// integrity：digest 与报文字节不符（digest.go）
	suite := mustSuite(t, "WOP-RSA3072-SHA256")
	if err := ValidateContentDigest(suite, DigestHeaderValue(suite, []byte("a")), []byte("b")); err == nil {
		t.Fatal("篡改字节应拒绝")
	} else if we := err.(*Error); we.Message != "x-wop-content-digest 与线上报文字节不匹配" {
		t.Errorf("integrity 文案 = %q", we.Message)
	}
}
