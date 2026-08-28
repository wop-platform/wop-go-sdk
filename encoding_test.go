package wop

import (
	"encoding/hex"
	"testing"
)

// F7/D10：base64url 无填充严格模式 + 小写 hex。
func TestB64URL(t *testing.T) {
	roundtrip := []string{"", "a", "ab", "abc", "abcd", "AAECAwQFBgcICQ=="} // 最后项作普通串处理
	for _, s := range roundtrip {
		enc := EncodeB64URL([]byte(s))
		if len(enc)%4 == 0 && len(enc) > 0 {
			// 无填充编码不出现 '='
			for i := 0; i < len(enc); i++ {
				if enc[i] == '=' {
					t.Fatalf("encoded %q contains '='", enc)
				}
			}
		}
		dec, err := DecodeB64URL(enc)
		if err != nil {
			t.Fatalf("roundtrip %q: %v", s, err)
		}
		if string(dec) != s {
			t.Fatalf("roundtrip %q → %q", s, dec)
		}
	}

	mustReject := []string{
		"abc=",  // 填充字符（F6 严格无填充）
		"ab+c",  // 标准字母表 '+'（F6 字母表）
		"ab/c",  // 标准字母表 '/'
		"ab c",  // 空白
		"a!c",   // 非法字符
		"abcde", // 长度模 4 余 1
	}
	for _, s := range mustReject {
		if _, err := DecodeB64URL(s); err == nil {
			t.Errorf("DecodeB64URL(%q) 应拒绝", s)
		}
	}
}

func TestLowerHex(t *testing.T) {
	got := LowerHex([]byte{0xAB, 0x00, 0x0f, 0xFF})
	if got != "ab000fff" {
		t.Errorf("LowerHex = %q, want ab000fff", got)
	}
	if UpperHex := hex.EncodeToString([]byte{0xAB}); UpperHex != "ab" {
		t.Errorf("sanity: hex.EncodeToString should be lowercase, got %q", UpperHex)
	}
}

// F2：Java-URLEncoder 语义（空格→%20、'+'→%2B、'~'→%7E、".-*_" 保留）。
func TestURLEncodeJava(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"hello world", "hello%20world"},
		{"a+b", "a%2Bb"},
		{"a~b", "a%7Eb"},
		{"a*b", "a*b"},
		{"a.b-c_d", "a.b-c_d"},
		{"中文", "%E4%B8%AD%E6%96%87"},
		{"a/b", "a%2Fb"},
		{"a(b)", "a%28b%29"},
		{"!x", "%21x"},
		{"x-wop-encrypt;L2", "x-wop-encrypt%3BL2"},
		{"sha-256 4cf7", "sha-256%204cf7"},
	}
	for _, tc := range cases {
		if got := URLEncodeJava(tc.in); got != tc.want {
			t.Errorf("URLEncodeJava(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TrimAll：去首尾空白 + 连续空白折叠为单空格（Java \\s+ 语义，含 \x0B）。
func TestTrimAll(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"  a \t\n b  ", "a b"},
		{"a\x0bb", "a b"},
		{"a\r\n\rb", "a b"},
		{"already clean", "already clean"},
	}
	for _, tc := range cases {
		if got := TrimAll(tc.in); got != tc.want {
			t.Errorf("TrimAll(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
