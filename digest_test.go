package wop

import "testing"

// D2/D3/I1/I5：x-wop-content-digest = "<sha-256|sm3> 恰一空格 64 位小写hex"，
// 算法随套件族，跨族拒绝，多余空白拒绝而非容忍。
func TestDigest_VectorByteLevel(t *testing.T) {
	v := loadGoldenVectors(t)
	for _, d := range v.Digests {
		var suite Suite
		switch d.Algorithm {
		case "SHA-256":
			suite = mustSuite(t, "WOP-RSA3072-SHA256")
		case "SM3":
			suite = mustSuite(t, "WOP-SM2-SM3")
		default:
			t.Fatalf("未知摘要算法 %q", d.Algorithm)
		}
		sum := suite.Digest([]byte(d.Input))
		if got := LowerHex(sum); got != d.ExpectedHex {
			t.Errorf("%s: digest hex = %s, want %s", d.ID, got, d.ExpectedHex)
		}
		if got := DigestHeaderValue(suite, []byte(d.Input)); got != d.ExpectedHeader {
			t.Errorf("%s: header = %q, want %q", d.ID, got, d.ExpectedHeader)
		}
	}
}

func TestParseContentDigest_Strict(t *testing.T) {
	good := "sha-256 23592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf"
	tag, hexSum, err := ParseContentDigest(good)
	if err != nil || tag != "sha-256" || hexSum != good[8:] {
		t.Fatalf("parse good: tag=%q hex=%q err=%v", tag, hexSum, err)
	}

	reject := []string{
		"",
		"sha-256",
		"sha-256 ",
		" sha-256 " + good[8:], // 首部空白
		"sha-256  " + good[8:], // 双空格（D2 恰一空格）
		"sha-256\t" + good[8:], // tab 分隔
		"sha-256 " + "23592263765CF506D07CC8614C09067E6DE38E64C53E5B672C022532D01737CF", // 大写 hex
		"SHA-256 " + good[8:], // 大写 tag
		"sha-256 3592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737cf", // 63 hex
		"sha-256 " + good[8:] + "f", // 65 hex
		"sha-256 z3592263765cf506d07cc8614c09067e6de38e64c53e5b672c022532d01737c", // 非 hex 字符
		"sha-512 " + good[8:],   // 未支持 tag
		"sm3 " + good[8:] + "x", // 长度非法
	}
	for _, s := range reject {
		if _, _, err := ParseContentDigest(s); err == nil {
			t.Errorf("ParseContentDigest(%q) 应拒绝", s)
		} else if we, ok := err.(*Error); !ok || we.Code != CodeProtocol {
			t.Errorf("ParseContentDigest(%q): 错误类 = %v, want CodeProtocol", s, err)
		}
	}
}

// I5：digest 标签与套件族强耦合，跨族拒绝。
func TestValidateContentDigest_FamilyCoupling(t *testing.T) {
	rsa := mustSuite(t, "WOP-RSA3072-SHA256")
	sm2 := mustSuite(t, "WOP-SM2-SM3")
	body := []byte("payload")
	sm3Header := DigestHeaderValue(sm2, body)

	err := ValidateContentDigest(rsa, sm3Header, body)
	if err == nil {
		t.Fatal("RSA 套件 + sm3 标签应跨族拒绝")
	}
	if we := err.(*Error); we.Code != CodeProtocol {
		t.Errorf("跨族错误类 = %s, want CodeProtocol", we.Code)
	}

	if err := ValidateContentDigest(sm2, sm3Header, body); err != nil {
		t.Fatalf("同族校验应通过: %v", err)
	}
}

// D2：摘要对象 = 线上原始报文字节（L2 时即密文载体），不匹配 → 完整性类明确错误。
func TestValidateContentDigest_Match(t *testing.T) {
	rsa := mustSuite(t, "WOP-RSA3072-SHA256")
	wire := []byte(`{"encrypted":"KrHINqF-kltl2OC1j5_c2A"}`)

	if err := ValidateContentDigest(rsa, DigestHeaderValue(rsa, wire), wire); err != nil {
		t.Fatalf("匹配应通过: %v", err)
	}

	tampered := append([]byte{}, wire...)
	tampered[len(tampered)-1] ^= 0x01
	err := ValidateContentDigest(rsa, DigestHeaderValue(rsa, wire), tampered)
	if err == nil {
		t.Fatal("篡改后应不匹配")
	}
	if we := err.(*Error); we.Code != CodeDigestMismatch {
		t.Errorf("不匹配错误类 = %s, want CodeDigestMismatch", we.Code)
	}
}

func mustSuite(t *testing.T, securityReq string) Suite {
	t.Helper()
	s, err := ParseSuite(securityReq)
	if err != nil {
		t.Fatalf("ParseSuite(%s): %v", securityReq, err)
	}
	return s
}
