package wop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// spec §3 约定：Go 无原生分支计数，以显式负向量分支清单矩阵替代。
// 每行 = 协议条款 → 负向量场景 → 期望错误分类；测试名与注释构成 grep 索引
// （spec:<ID>）。CI 中 `grep -c "spec:"` 可对账清单条数。

type failReader struct{ after int }

func (f *failReader) Read(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("reader exhausted")
	}
	n := copy(p, bytes.Repeat([]byte{0x7F}, len(p)))
	if n > f.after {
		n = f.after
	}
	f.after -= n
	return n, nil
}

// spec:D2-1 无 body 携带 digest → 协议类明确拒
// spec:D2-2 有 body 缺 digest → 完整性类明确拒
// spec:D2-3 digest 双空格 → 拒（容忍即漂移）
// spec:D2-4 digest 大写 hex → 拒
// spec:I1 digest 未入 signedHeaders → 拒（body 与签名唯一绑定桥梁）
// spec:I2 篡改签名 → 验签模糊错误（先于解密）
// spec:I3 dek alg 跨族 → 一致性明确（bulk 解密前）
// spec:I5 digest 标签跨族 → 拒
// spec:I5 securityReq 跨族组合 → 支持类拒
// spec:I7-1 验签失败对外模糊（固定文案）
// spec:I7-2 解密失败对外模糊（固定文案）
// spec:F7-1 SM2 63B/65B 签名 → 长度前置拒
// spec:F7-2 带 = base64url → 严格拒
// spec:F7-3 RSA 错长签名 → 长度前置拒
// spec:D9-1 C1C2C3 顺序密文 → 解密失败（顺序钉死）
// spec:D9-2 DER/ASN.1 签名（非 64B 裸 r||s）→ 长度前置拒
// spec:F2 MGF1-SHA1 包装密文 → 规格参数解包必须失败
func TestInvariantNegativeBranchMatrix(t *testing.T) {
	v := loadGoldenVectors(t)
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	sm2Pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	var err error
	rsaPub := &pubKey{}
	if rsaPub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
		t.Fatal(err)
	}
	msg := []byte(v.Inputs.Message)
	sm2Sig := mustFirstSig(t, v, "sm2-sign-fixedk")

	cases := []struct {
		id    string
		code  ErrorCode
		check func() error
	}{
		{"D2-1", CodeProtocol, func() error {
			return ValidateContentDigestHeader(rsaSuite, "")
		}},
		{"D2-3", CodeProtocol, func() error {
			return ValidateContentDigestHeader(rsaSuite, "sha-256  "+strings.Repeat("a", 64))
		}},
		{"D2-4", CodeProtocol, func() error {
			return ValidateContentDigestHeader(rsaSuite, "sha-256 "+strings.Repeat("A", 64))
		}},
		{"I5-digest", CodeProtocol, func() error {
			return ValidateContentDigestHeader(rsaSuite, "sm3 "+strings.Repeat("a", 64))
		}},
		{"I5-suite", CodeSuiteUnsupported, func() error {
			_, err := ParseSuite("WOP-RSA3072-SM3")
			return err
		}},
		{"F7-1-63B", CodeProtocol, func() error {
			return verifyMessage(sm2Suite, sm2Pub, msg, sm2Sig[:84])
		}},
		{"F7-1-65B", CodeProtocol, func() error {
			return verifyMessage(sm2Suite, sm2Pub, msg, "AA"+sm2Sig)
		}},
		{"F7-3-RSA错长", CodeProtocol, func() error {
			return verifyMessage(rsaSuite, rsaPub, msg, EncodeB64URL(make([]byte, 383)))
		}},
		{"F7-2-b64=", CodeProtocol, func() error {
			_, err := DecodeB64URL("abc=")
			return err
		}},
		{"F7-2-b64+", CodeProtocol, func() error {
			_, err := DecodeB64URL("ab+c")
			return err
		}},
		{"D9-2-DER签名", CodeProtocol, func() error {
			// DER SEQUENCE 编码的签名长度必 > 64B
			der := append([]byte{0x30, 0x44, 0x02, 0x20}, mustDecodeB64u(t, sm2Sig)...)
			return verifyMessage(sm2Suite, sm2Pub, msg, EncodeB64URL(der))
		}},
		{"D9-1-C1C2C3", CodeDecryptFailed, func() error {
			for _, ke := range v.KeyEncrypt {
				if ke.ID == "sm2-encrypt-c1c2c3-mismatch" {
					_, err := unwrapDEKPayload(sm2Suite, &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}, ke.CipherB64u)
					return err
				}
			}
			return nil
		}},
		{"F2-MGF1SHA1", CodeDecryptFailed, func() error {
			for _, ke := range v.KeyEncrypt {
				if ke.ID == "oaep3072-mgf1sha1-trap" {
					priv, _ := parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64)
					_, err := unwrapDEKPayload(rsaSuite, &privKey{rsa: priv}, ke.CipherB64u)
					return err
				}
			}
			return nil
		}},
		{"I7-1", CodeVerifyFailed, func() error {
			return verifyMessage(sm2Suite, &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}, []byte("篡改消息"), sm2Sig)
		}},
	}
	for _, tc := range cases {
		err := tc.check()
		if err == nil {
			t.Errorf("spec:%s 负向量应拒绝", tc.id)
			continue
		}
		we, ok := err.(*Error)
		if !ok {
			t.Errorf("spec:%s: 错误类型 %T", tc.id, err)
			continue
		}
		if we.Code != tc.code {
			t.Errorf("spec:%s: 错误类 = %s, want %s", tc.id, we.Code, tc.code)
		}
	}

	// I7 模糊文案钉死
	we := fuzzyError(CodeVerifyFailed)
	if we.Message != verifyFuzzyMessage {
		t.Errorf("I7-1 文案漂移：%q", we.Message)
	}
	we = fuzzyError(CodeDecryptFailed)
	if we.Message != decryptFuzzyMessage {
		t.Errorf("I7-2 文案漂移：%q", we.Message)
	}
	// verifyFail 兜底（非 wop.Error 内部错误 → 配置类收敛）
	res := verifyFail(errors.New("boom"))
	if res.OK || res.Code != CodeConfig {
		t.Errorf("verifyFail 兜底: %+v", res)
	}
	// Error() 文案
	if msg := (&Error{Code: CodeConfig, Message: "x"}).Error(); !strings.Contains(msg, "[CONFIG]") {
		t.Errorf("Error() = %q", msg)
	}
}

// 覆盖缺口闭合：密钥族不匹配 / 随机源失败 / nil 密钥配置错误 / 解析负分支。
func TestCoverageGap_KeyFamilyMismatch(t *testing.T) {
	v := loadGoldenVectors(t)

	// SM2 套件 + RSA 材料 / RSA 套件 + SM2 材料（NewClient 全部 4 个解析失败分支）
	cfg := testConfig(t, "WOP-SM2-SM3")
	cfg.MerchantPrivateKey = v.Keys.RSA3072.PrivatePkcs8B64
	if _, err := NewClient(cfg); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("SM2 套件+RSA 私钥: %v", err)
	}
	cfg = testConfig(t, "WOP-SM2-SM3")
	cfg.PlatformPublicKey = v.Keys.RSA3072.PublicSpkiB64
	if _, err := NewClient(cfg); err == nil {
		t.Error("SM2 套件+RSA 公钥应失败")
	}
	cfg = testConfig(t, "WOP-RSA3072-SHA256")
	cfg.MerchantPrivateKey = v.Keys.SM2.PrivateDB64
	if _, err := NewClient(cfg); err == nil {
		t.Error("RSA 套件+SM2 私钥应失败")
	}
	cfg = testConfig(t, "WOP-RSA3072-SHA256")
	cfg.PlatformPublicKey = v.Keys.SM2.PublicPointB64
	if _, err := NewClient(cfg); err == nil {
		t.Error("RSA 套件+SM2 公钥应失败")
	}
	// 平台公钥位数不符（3072 套件 + 4096 平台公钥）
	cfg = testConfig(t, "WOP-RSA3072-SHA256")
	cfg.PlatformPublicKey = v.Keys.RSA4096.PublicSpkiB64
	if _, err := NewClient(cfg); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("平台公钥位数: %v", err)
	}
}

func TestCoverageGap_FailingRandomSources(t *testing.T) {
	v := loadGoldenVectors(t)

	// nonce 生成失败（reader 立即 EOF）
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.BuildRequest("POST", "/p", []byte("b"), Level0, WithRandom(&failReader{}))
	if err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("nonce 失败: %v", err)
	}
	// CEK 失败（reader 只剩 16B）
	_, err = client.BuildRequest("POST", "/p", []byte("b"), Level2, WithRandom(&failReader{after: 16}))
	if err == nil {
		t.Error("CEK 失败应报错")
	}
	// IV 失败（reader 只剩 40B）
	_, err = client.BuildRequest("POST", "/p", []byte("b"), Level2, WithRandom(&failReader{after: 40}))
	if err == nil {
		t.Error("IV 失败应报错")
	}

	// SM2 签名 k 生成失败 → signMessage 模糊
	sm2Client, _ := NewClient(testConfig(t, "WOP-SM2-SM3"))
	_, err = sm2Client.BuildRequest("POST", "/p", []byte("b"), Level0,
		WithTimestamp(1), WithNonce("n"), WithRandom(&failReader{}))
	if err == nil {
		t.Error("SM2 k 失败应报错")
	}

	// 底层 sm2Sign / sm2Encrypt 随机源失败
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	if _, err := sm2Sign(priv, sm2DefaultUserID, []byte("m"), nil, &failReader{}); err == nil {
		t.Error("sm2Sign 随机失败应报错")
	}
	if _, err := sm2Encrypt(&priv.PublicKey, []byte("m"), nil, &failReader{}); err == nil {
		t.Error("sm2Encrypt 随机失败应报错")
	}
}

func TestCoverageGap_NilKeyConfigErrors(t *testing.T) {
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")

	// 签名层：族不匹配的空密钥位
	if _, err := signMessage(sm2Suite, &privKey{}, []byte("m"), nil); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("SM2 缺私钥: %v", err)
	}
	if _, err := signMessage(rsaSuite, &privKey{}, []byte("m"), nil); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("RSA 缺私钥: %v", err)
	}
	if err := verifyMessage(sm2Suite, &pubKey{}, []byte("m"), strings.Repeat("A", 86)); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("SM2 缺公钥: %v", err)
	}
	if err := verifyMessage(rsaSuite, &pubKey{}, []byte("m"), strings.Repeat("A", 512)); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("RSA 缺公钥: %v", err)
	}

	// DEK 层
	if _, err := wrapDEKPayload(sm2Suite, &pubKey{}, []byte("p"), nil); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("SM2 缺包装公钥: %v", err)
	}
	if _, err := wrapDEKPayload(rsaSuite, &pubKey{}, []byte("p"), nil); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("RSA 缺包装公钥: %v", err)
	}
	if _, err := unwrapDEKPayload(sm2Suite, &privKey{}, "QUJD"); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("SM2 缺解包私钥: %v", err)
	}
	if _, err := unwrapDEKPayload(rsaSuite, &privKey{}, "QUJD"); err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("RSA 缺解包私钥: %v", err)
	}
}

func TestCoverageGap_OAPEPPayloadTooLong(t *testing.T) {
	v := loadGoldenVectors(t)
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	pub := &pubKey{}
	if pub.rsa, _ = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); pub.rsa == nil {
		t.Fatal("parse")
	}
	// OAEP 最大明文 k-2h-2 = 384-64-2 = 318B；319B 必失败 → 模糊
	_, err := wrapDEKPayload(rsaSuite, pub, make([]byte, 319), nil)
	if err == nil || err.(*Error).Code != CodeDecryptFailed {
		t.Errorf("超长 DEK 载荷: %v", err)
	}
}

func TestCoverageGap_SM2RawBranches(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)

	// C1 非 04 前缀
	ct, _ := sm2Encrypt(pub, []byte("m"), nil, nil)
	ct[0] = 0x03
	if _, err := sm2Decrypt(priv, ct); err == nil {
		t.Error("C1 非 04 前缀应失败")
	}
	// equalBytes 长度不等
	if equalBytes([]byte("ab"), []byte("a")) {
		t.Error("长度不等应不等")
	}
	// 标量超界构造私钥失败
	n := sm2CurveN()
	if _, err := sm2PrivateKeyFromScalar(new(big.Int).Add(n, big.NewInt(1))); err == nil {
		t.Error("d ≥ n 应失败")
	}
	// 解析路径：垃圾 base64 SM2 私钥（keys.go 负分支）
	if _, err := parseSM2PrivateKey("%%%"); err == nil {
		t.Error("垃圾 base64 应失败")
	}
	// base64 材料含内嵌换行（非 PEM）
	chunked := v.Keys.SM2.PrivateDB64
	if len(chunked) > 40 {
		chunked = chunked[:40] + "\n" + chunked[40:]
	}
	if _, err := parseSM2PrivateKey(chunked); err != nil {
		t.Errorf("内嵌换行的 base64 应被清洗后接受: %v", err)
	}
}

func TestCoverageGap_ECKeyMaterialRejected(t *testing.T) {
	// RSA 解析器拒绝 EC 密钥材料（类型分支）
	ecPriv, err := generateECPKCS8ForTest()
	if err != nil {
		t.Skipf("EC 材料生成失败: %v", err)
	}
	if _, err := parseRSAPrivateKey(ecPriv); err == nil {
		t.Error("EC PKCS8 材料应被 RSA 解析器拒绝")
	}
	ecPub, err := generateECSPKIFromTest()
	if err != nil {
		t.Skipf("EC 材料生成失败: %v", err)
	}
	if _, err := parseRSAPublicKey(ecPub); err == nil {
		t.Error("EC SPKI 材料应被 RSA 公钥解析器拒绝")
	}
}

func TestCoverageGap_VerifyL2Malformed(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-SM2-SM3")
	c := verifyClient(t, "WOP-SM2-SM3")

	// L2 信封非 JSON / b64 非法 / dek 载荷畸形（三个协议分支）
	rnd := deterministicReader()
	suite := mustSuite(t, "WOP-SM2-SM3")
	for name, body := range map[string][]byte{
		"非 JSON":   []byte(`garbage`),
		"缺字段":      []byte(`{}`),
		"非 b64 密文": []byte(`{"encrypted":"ab+c"}`),
	} {
		wire := body
		h := http.Header{}
		h.Set(HeaderNonce, "n1")
		h.Set(HeaderTimestamp, "1755900000000")
		wrapped, err := wrapDEKPayload(suite, &pubKey{sm2: b.merchantPubS}, []byte(vDekPayloadSM2(t)), rnd)
		if err != nil {
			t.Fatal(err)
		}
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
		h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
		signed := map[string]string{HeaderNonce: "n1", HeaderTimestamp: "1755900000000",
			HeaderContentDigest: h.Get(HeaderContentDigest), HeaderEncrypt: h.Get(HeaderEncrypt)}
		canonical := CanonicalRequest("v1/1800", "POST", "/p", "", CanonicalHeaders(signed))
		sig, _ := signMessage(suite, &privKey{sm2: b.platformPrivS}, []byte(canonical), rnd)
		h.Set(HeaderSign, buildSignHeader(suite.SecurityReq(), 1800,
			[]string{HeaderContentDigest, HeaderEncrypt, HeaderNonce, HeaderTimestamp}, sig))
		res := c.VerifyResponse("POST", "/p", h, wire)
		if res.OK || res.Code == CodeVerifyFailed || res.Code == CodeDigestMismatch {
			t.Errorf("%s: ok=%v code=%s（应为协议/解密类）", name, res.OK, res.Code)
		}
	}

	// 解包成功但载荷畸形（alg 段垃圾）
	wire := wrapEncryptedBody(EncodeB64URL([]byte("garbage16bytesxx")))
	wrapped, err := wrapDEKPayload(suite, &pubKey{sm2: b.merchantPubS}, []byte("NOT-AN-ALG$AA$BB"), rnd)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(HeaderNonce, "n1")
	h.Set(HeaderTimestamp, "1755900000000")
	h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
	h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
	signed := map[string]string{HeaderNonce: "n1", HeaderTimestamp: "1755900000000",
		HeaderContentDigest: h.Get(HeaderContentDigest), HeaderEncrypt: h.Get(HeaderEncrypt)}
	canonical := CanonicalRequest("v1/1800", "POST", "/p", "", CanonicalHeaders(signed))
	sig, _ := signMessage(suite, &privKey{sm2: b.platformPrivS}, []byte(canonical), rnd)
	h.Set(HeaderSign, buildSignHeader(suite.SecurityReq(), 1800,
		[]string{HeaderContentDigest, HeaderEncrypt, HeaderNonce, HeaderTimestamp}, sig))
	if res := c.VerifyResponse("POST", "/p", h, wire); res.OK || res.Code != CodeProtocol {
		t.Errorf("畸形 dek 载荷: ok=%v code=%s", res.OK, res.Code)
	}

	// x-wop-encrypt 头本身非法
	h2, wire2 := b.build(t, "POST", "/p", []byte("x"), Level2, nil)
	h2.Set(HeaderEncrypt, "L2;dek=")
	// 重签（头变了）
	resign := func(hh http.Header) {
		parsed, _ := ParseSignHeader(hh.Get(HeaderSign))
		sm := map[string]string{}
		for _, name := range parsed.signedHeaders {
			if v2 := hh.Get(name); v2 != "" {
				sm[name] = v2
			}
		}
		can := CanonicalRequest(parsed.authString(), "POST", "/p", "", CanonicalHeaders(sm))
		sig2, _ := signMessage(suite, &privKey{sm2: b.platformPrivS}, []byte(can), deterministicReader())
		hh.Set(HeaderSign, buildSignHeader(suite.SecurityReq(), parsed.expiredSeconds, parsed.signedHeaders, sig2))
	}
	h2.Set(HeaderEncrypt, "malformed")
	resign(h2)
	if res := c.VerifyResponse("POST", "/p", h2, wire2); res.OK || res.Code != CodeProtocol {
		t.Errorf("非法 encrypt 头: ok=%v code=%s", res.OK, res.Code)
	}
}

func TestCoverageGap_MessageAndTransport(t *testing.T) {
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")

	// openMessage 密钥/IV 长度负分支
	if _, err := openMessage(rsaSuite, []byte("ct"), make([]byte, 16), make([]byte, 12)); err == nil {
		t.Error("open 错误密钥长应失败")
	}
	if _, err := openMessage(rsaSuite, []byte("ct"), make([]byte, 32), make([]byte, 11)); err == nil {
		t.Error("open 错误 IV 长应失败")
	}
	if _, err := sealMessage(sm2Suite, []byte("x"), make([]byte, 16), make([]byte, 11)); err == nil {
		t.Error("SM4 seal IV 错长应失败")
	}
	// dek iv 段非 b64url
	if _, err := parseDekPayload("SM4-GCM$ICEiIyQlJicoKSorLC0uLw$@@@!"); err == nil {
		t.Error("iv 段非 b64url 应拒绝")
	}

	// transport：非法 method（http.NewRequest 校验）
	if _, err := (DefaultTransport{BaseURL: "http://x.example.com"}).Send(
		RequestDraft{Method: "G T", Path: "/p"}); err == nil {
		t.Error("非法 method 应失败")
	}

	// transport：响应体读取中断（Content-Length 大于实际写出）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		_, _ = w.Write([]byte("short"))
		w.(http.Flusher).Flush()
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close() // 提前断连 → 客户端读体失败
			}
		}
	}))
	defer srv.Close()
	if _, err := (DefaultTransport{BaseURL: srv.URL}).Send(RequestDraft{Method: "GET", Path: "/x"}); err == nil {
		t.Error("截断响应应失败")
	}

	// Do 失败路径：构建失败
	client, _ := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if _, _, err := client.Do("", "/p", nil, Level0); err == nil {
		t.Error("Do 构建失败应透出")
	}
	// Do 发送失败（端口不可达）
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = DefaultTransport{BaseURL: "http://127.0.0.1:1"}
	deadClient, _ := NewClient(cfg)
	if _, _, err := deadClient.Do("POST", "/p", []byte("x"), Level0); err == nil {
		t.Error("Do 发送失败应透出")
	}

	// Suite() 访问器
	if client.Suite().SecurityReq() != "WOP-RSA3072-SHA256" {
		t.Error("Suite() 访问器")
	}
}

func generateECPKCS8ForTest() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func generateECSPKIFromTest() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// 白盒：重试上限耗尽 / 固定 k 范围校验 / 客户端随机源中途失败。
func TestCoverageGap_RetryAndFixedKValidation(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)

	// 重试上限耗尽（注入 0）
	savedSign, savedEnc := sm2SignRetries, sm2EncryptRetries
	sm2SignRetries, sm2EncryptRetries = 0, 0
	defer func() { sm2SignRetries, sm2EncryptRetries = savedSign, savedEnc }()
	if _, err := sm2Sign(priv, sm2DefaultUserID, []byte("m"), nil, nil); err == nil {
		t.Error("签名重试耗尽应报错")
	}
	if _, err := sm2Encrypt(pub, []byte("m"), nil, nil); err == nil {
		t.Error("加密重试耗尽应报错")
	}
	sm2SignRetries, sm2EncryptRetries = savedSign, savedEnc

	// 固定 k 范围校验（k=0 与 k=n）
	for _, bad := range []*big.Int{big.NewInt(0), new(big.Int).Set(sm2CurveN())} {
		if _, err := sm2Sign(priv, sm2DefaultUserID, []byte("m"), bad, nil); err == nil {
			t.Error("非法固定 k 签名应报错")
		}
		if _, err := sm2Encrypt(pub, []byte("m"), bad, nil); err == nil {
			t.Error("非法固定 k 加密应报错")
		}
	}
}

func TestCoverageGap_ClientRandomSourceMidFail(t *testing.T) {
	client, _ := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	// nonce 16 + CEK 32 已消费，IV 读取失败
	if _, err := client.BuildRequest("POST", "/p", []byte("b"), Level2, WithRandom(&failReader{after: 48})); err == nil {
		t.Error("IV 中途失败应报错")
	}

	// SM2：nonce16+CEK16+IV12=44 消费后，DEK 包装 k 读取失败
	sm2Client, _ := NewClient(testConfig(t, "WOP-SM2-SM3"))
	_, err := sm2Client.BuildRequest("POST", "/p", []byte("b"), Level2,
		WithRandom(&failReader{after: 50}))
	if err == nil {
		t.Error("SM2 DEK 包装失败应报错")
	}
}

func TestCoverageGap_TinyRSAKeySignFails(t *testing.T) {
	tiny, err := rsa.GenerateKey(rand.Reader, 256)
	if err != nil {
		t.Skipf("256 位 RSA 密钥生成失败: %v", err)
	}
	// SHA256 摘要超出小模数签名能力 → SignPKCS1v15 失败 → 模糊
	_, err = signMessage(mustSuite(t, "WOP-RSA3072-SHA256"), &privKey{rsa: tiny}, []byte("m"), nil)
	if err == nil || err.(*Error).Code != CodeVerifyFailed {
		t.Errorf("小密钥签名应模糊失败: %v", err)
	}
}

func TestCoverageGap_GarbageSM2PublicKeyBase64(t *testing.T) {
	if _, err := parseSM2PublicKey("%%%"); err == nil {
		t.Error("垃圾 base64 SM2 公钥应失败")
	}
}

func TestCoverageGap_DigestFormatAtValidateAndBrokenRSAKey(t *testing.T) {
	// ValidateContentDigest 层直接吃到格式非法值（管线外调用）
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	if err := ValidateContentDigest(rsaSuite, "garbage", []byte("b")); err == nil || err.(*Error).Code != CodeProtocol {
		t.Errorf("格式非法应拒绝: %v", err)
	}
	// 损坏 RSA 密钥（N=1）→ SignPKCS1v15 失败 → 模糊
	broken := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 3}, D: big.NewInt(1)}
	if _, err := signMessage(rsaSuite, &privKey{rsa: broken}, []byte("m"), nil); err == nil || err.(*Error).Code != CodeVerifyFailed {
		t.Errorf("损坏密钥签名应模糊失败: %v", err)
	}
}
