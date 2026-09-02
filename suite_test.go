package wop

import "testing"

// spec F1 / crypto-strategy-spec §2：securityReq 三段式解析、跨族/非法拒绝、错误分类（解析类/支持类）。
func TestParseSuite_ValidSuites(t *testing.T) {
	cases := []struct {
		securityReq string
		family      Family
		keyBits     int
		signAlg     string
		msgAlg      string
		keyWrap     string
		digestTag   string
	}{
		{"WOP-RSA3072-SHA256", FamilyRSA, 3072, "SHA256withRSA", "AES-256-GCM", "RSA-3072-OAEP", "sha-256"},
		{"WOP-RSA4096-SHA256", FamilyRSA, 4096, "SHA256withRSA", "AES-256-GCM", "RSA-4096-OAEP", "sha-256"},
		{"WOP-SM2-SM3", FamilySM2, 0, "SM3withSM2", "SM4-GCM", "SM2", "sm3"},
	}
	for _, tc := range cases {
		s, err := ParseSuite(tc.securityReq)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.securityReq, err)
		}
		if s.SecurityReq() != tc.securityReq {
			t.Errorf("SecurityReq = %q, want %q", s.SecurityReq(), tc.securityReq)
		}
		if s.Family() != tc.family {
			t.Errorf("%s: Family = %q, want %q", tc.securityReq, s.Family(), tc.family)
		}
		if s.KeyBits() != tc.keyBits {
			t.Errorf("%s: KeyBits = %d, want %d", tc.securityReq, s.KeyBits(), tc.keyBits)
		}
		if s.SignAlgorithm() != tc.signAlg {
			t.Errorf("%s: SignAlgorithm = %q, want %q", tc.securityReq, s.SignAlgorithm(), tc.signAlg)
		}
		if s.MessageAlgorithm() != tc.msgAlg {
			t.Errorf("%s: MessageAlgorithm = %q, want %q", tc.securityReq, s.MessageAlgorithm(), tc.msgAlg)
		}
		if s.KeyWrapAlgorithm() != tc.keyWrap {
			t.Errorf("%s: KeyWrapAlgorithm = %q, want %q", tc.securityReq, s.KeyWrapAlgorithm(), tc.keyWrap)
		}
		if s.DigestTag() != tc.digestTag {
			t.Errorf("%s: DigestTag = %q, want %q", tc.securityReq, s.DigestTag(), tc.digestTag)
		}
		if s.IsSM2() != (tc.family == FamilySM2) {
			t.Errorf("%s: IsSM2 = %v", tc.securityReq, s.IsSM2())
		}
	}
}

// spec §2.4：空值/格式错误 → 解析类（明确）；算法不支持/跨族 → 支持类（明确）。
func TestParseSuite_Rejects(t *testing.T) {
	cases := []struct {
		securityReq string
		code        ErrorCode
	}{
		{"", CodeConfiguration},
		{"   ", CodeConfiguration},
		{"RSA3072-SHA256", CodeConfiguration},           // 缺 WOP 前缀
		{"WOP-RSA3072", CodeConfiguration},              // 非三段
		{"WOP-RSA3072-SHA256-EXTRA", CodeConfiguration}, // 四段
		{"XOP-RSA3072-SHA256", CodeConfiguration},       // 前缀非 WOP
		{"WOP-RSA2048-SHA256", CodeConfiguration},       // 密钥算法不在支持列表
		{"WOP-ECDSA-SHA256", CodeConfiguration},
		{"WOP-RSA3072-SHA512", CodeConfiguration}, // 摘要算法不在支持列表
		{"WOP-RSA3072-SM3", CodeConfiguration},    // 国际密钥+国密摘要，跨族（I5）
		{"WOP-SM2-SHA256", CodeConfiguration},     // 国密密钥+国际摘要，跨族（I5）
	}
	for _, tc := range cases {
		_, err := ParseSuite(tc.securityReq)
		if err == nil {
			t.Fatalf("%q: expected error", tc.securityReq)
		}
		we, ok := err.(*Error)
		if !ok {
			t.Fatalf("%q: error type = %T, want *wop.Error", tc.securityReq, err)
		}
		if we.Code != tc.code {
			t.Errorf("%q: code = %s, want %s (msg=%q)", tc.securityReq, we.Code, tc.code, we.Message)
		}
		if we.Message == "" {
			t.Errorf("%q: 明确类错误必须携带可读 message", tc.securityReq)
		}
	}
}

func TestParseSuite_TrimsWhitespace(t *testing.T) {
	s, err := ParseSuite("  WOP-SM2-SM3  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.SecurityReq() != "WOP-SM2-SM3" {
		t.Errorf("SecurityReq = %q, want canonical WOP-SM2-SM3", s.SecurityReq())
	}
}
