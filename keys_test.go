package wop

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"
)

// D12 密钥分发契约：RSA=SPKI/PKCS8（PEM 或 Base64 单行）；
// SM2 公钥=未压缩点 04‖X‖Y（65B Base64）、私钥=d 32B 大端标量。
func TestParseRSAKeys_VectorMaterial(t *testing.T) {
	v := loadGoldenVectors(t)

	pub, err := parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64)
	if err != nil {
		t.Fatalf("SPKI base64 公钥解析失败: %v", err)
	}
	if pub.N.BitLen() != 3072 {
		t.Errorf("公钥位数 = %d, want 3072", pub.N.BitLen())
	}

	priv, err := parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64)
	if err != nil {
		t.Fatalf("PKCS8 base64 私钥解析失败: %v", err)
	}
	if priv.PublicKey.N.Cmp(pub.N) != 0 {
		t.Error("私钥与公钥不配对")
	}

	// PEM 包装等价（商户常见格式）
	pemPub := "-----BEGIN PUBLIC KEY-----\n" + chunkBase64(v.Keys.RSA3072.PublicSpkiB64) + "\n-----END PUBLIC KEY-----\n"
	pub2, err := parseRSAPublicKey(pemPub)
	if err != nil || pub2.N.Cmp(pub.N) != 0 {
		t.Errorf("PEM 公钥解析: err=%v", err)
	}
	pemPriv := "-----BEGIN PRIVATE KEY-----\n" + chunkBase64(v.Keys.RSA3072.PrivatePkcs8B64) + "\n-----END PRIVATE KEY-----\n"
	priv2, err := parseRSAPrivateKey(pemPriv)
	if err != nil || priv2.N.Cmp(priv.N) != 0 {
		t.Errorf("PEM 私钥解析: err=%v", err)
	}
}

func TestParseRSAKeys_Rejects(t *testing.T) {
	cases := []struct {
		name  string
		pub   string
		priv  string
		stage string
	}{
		{"空公钥", "", "", "pub"},
		{"垃圾公钥", "not-base64!!!", "", "pub"},
		{"非 SPKI 内容", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", "", "pub"},
		{"空私钥", "", "", "priv"},
		{"非 PKCS8 内容", "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=", "", "priv"},
	}
	for _, tc := range cases {
		var err error
		if tc.stage == "pub" {
			_, err = parseRSAPublicKey(tc.pub)
		} else {
			_, err = parseRSAPrivateKey(tc.pub)
		}
		if err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
			continue
		}
		if we, ok := err.(*Error); !ok || we.Code != CodeConfig {
			t.Errorf("%s: 错误类 = %v, want CodeConfig", tc.name, err)
		}
	}
	if _, err := parseRSAPrivateKey(""); err == nil {
		t.Error("空私钥应拒绝")
	}
}

func TestParseSM2Keys_VectorMaterial(t *testing.T) {
	v := loadGoldenVectors(t)

	pub, err := parseSM2PublicKey(v.Keys.SM2.PublicPointB64)
	if err != nil {
		t.Fatalf("SM2 公钥点解析失败: %v", err)
	}
	var _ *ecdsa.PublicKey = pub

	priv, err := parseSM2PrivateKey(v.Keys.SM2.PrivateDB64)
	if err != nil {
		t.Fatalf("SM2 私钥标量解析失败: %v", err)
	}
	// d·G 必须等于分发公钥点（D12 材料自洽）
	if priv.PublicKey.X.Cmp(pub.X) != 0 || priv.PublicKey.Y.Cmp(pub.Y) != 0 {
		t.Error("SM2 私钥与公钥点不配对")
	}
}

func TestParseSM2Keys_Rejects(t *testing.T) {
	v := loadGoldenVectors(t)
	// 64B（缺 04 前缀与一个坐标字节）
	short := mustDecodeStd(t, v.Keys.SM2.PublicPointB64)[:64]
	// 非 04 前缀
	badPrefix := append([]byte{}, mustDecodeStd(t, v.Keys.SM2.PublicPointB64)...)
	badPrefix[0] = 0x03
	// 不在曲线上的"点"
	notOnCurve := append([]byte{0x04}, make([]byte, 64)...)
	notOnCurve[1] = 0x01

	pubReject := map[string][]byte{
		"64B 短点":  short,
		"非 04 前缀": badPrefix,
		"不在曲线上":   notOnCurve,
	}
	for name, raw := range pubReject {
		if _, err := parseSM2PublicKey(encodeStdB64(raw)); err == nil {
			t.Errorf("SM2 公钥 %s 应拒绝", name)
		} else if we, ok := err.(*Error); !ok || we.Code != CodeConfig {
			t.Errorf("SM2 公钥 %s: 错误类 = %v, want CodeConfig", name, err)
		}
	}

	privReject := map[string][]byte{
		"31B 短标量": make([]byte, 31),
		"33B 长标量": make([]byte, 33),
		"零标量":     make([]byte, 32),
	}
	for name, raw := range privReject {
		if _, err := parseSM2PrivateKey(encodeStdB64(raw)); err == nil {
			t.Errorf("SM2 私钥 %s 应拒绝", name)
		}
	}
	if _, err := parseSM2PrivateKey("!!!not-base64"); err == nil {
		t.Error("垃圾 base64 应拒绝")
	}
}

// RSA 密钥位数与套件强耦合（3072/4096），不符 → 配置类明确错误。
func TestValidateRSAKeySize(t *testing.T) {
	v := loadGoldenVectors(t)
	priv4096, err := parseRSAPrivateKey(v.Keys.RSA4096.PrivatePkcs8B64)
	if err != nil {
		t.Fatalf("4096 私钥解析失败: %v", err)
	}
	suite3072 := mustSuite(t, "WOP-RSA3072-SHA256")
	err = validateRSAKeySize(suite3072, priv4096)
	if err == nil {
		t.Fatal("3072 套件 + 4096 密钥应拒绝")
	}
	if we := err.(*Error); we.Code != CodeConfig {
		t.Errorf("错误类 = %s, want CodeConfig", we.Code)
	}
	suite4096 := mustSuite(t, "WOP-RSA4096-SHA256")
	if err := validateRSAKeySize(suite4096, priv4096); err != nil {
		t.Errorf("4096 套件应放行: %v", err)
	}
}

func mustDecodeStd(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := decodeKeyMaterial(s)
	if err != nil {
		t.Fatalf("decodeKeyMaterial(%s): %v", s, err)
	}
	return raw
}

func chunkBase64(s string) string {
	var out []byte
	for i, r := range s {
		out = append(out, byte(r))
		if (i+1)%64 == 0 {
			out = append(out, '\n')
		}
	}
	return string(out)
}

func encodeStdB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
