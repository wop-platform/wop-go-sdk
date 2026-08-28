package wop

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"net/http"
	"testing"
)

// platformResponseBuilder 模拟网关出站方向（SignFilter.post + CryptoFilter.post），
// 用于构造商户侧 VerifyResponse/VerifyCallback 的输入。
type platformResponseBuilder struct {
	suiteID       string
	platformPrivR *rsa.PrivateKey
	platformPrivS *ecdsa.PrivateKey
	merchantPubR  *rsa.PublicKey
	merchantPubS  *ecdsa.PublicKey
}

func newPlatformBuilder(t *testing.T, suiteID string) *platformResponseBuilder {
	t.Helper()
	v := loadGoldenVectors(t)
	b := &platformResponseBuilder{suiteID: suiteID}
	var err error
	if suiteID == "WOP-SM2-SM3" {
		b.platformPrivS = mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
		b.merchantPubS = mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
		return b
	}
	key := v.Keys.RSA3072
	if suiteID == "WOP-RSA4096-SHA256" {
		key = v.Keys.RSA4096
	}
	if b.platformPrivR, err = parseRSAPrivateKey(key.PrivatePkcs8B64); err != nil {
		t.Fatal(err)
	}
	if b.merchantPubR, err = parseRSAPublicKey(key.PublicSpkiB64); err != nil {
		t.Fatal(err)
	}
	return b
}

// build 产出平台签名响应（method/path 用于 canonical 重建）。
func (b *platformResponseBuilder) build(t *testing.T, method, path string, plaintext []byte, level Level, tamper func(*http.Header, []byte) []byte) (http.Header, []byte) {
	t.Helper()
	suite := mustSuite(t, b.suiteID)
	rnd := deterministicReader()

	var wire []byte
	h := http.Header{}
	h.Set(HeaderNonce, "resp-nonce-0001")
	h.Set(HeaderTimestamp, "1755900000000")

	if level == Level2 {
		cek := readBytes(t, rnd, suite.cekLen())
		iv := readBytes(t, rnd, gcmIVLen)
		ct, err := sealMessage(suite, plaintext, cek, iv)
		if err != nil {
			t.Fatal(err)
		}
		wire = wrapEncryptedBody(EncodeB64URL(ct))
		wrapped, err := wrapDEKPayload(suite, &pubKey{rsa: b.merchantPubR, sm2: b.merchantPubS},
			[]byte(buildDekPayload(suite.MessageAlgorithm(), cek, iv)), rnd)
		if err != nil {
			t.Fatal(err)
		}
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
	} else {
		wire = plaintext
	}
	if tamper != nil {
		wire = tamper(&h, wire)
	}
	if len(wire) > 0 {
		h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
	}

	signedMap := map[string]string{}
	for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
		if v := h.Get(name); v != "" {
			signedMap[name] = v
		}
	}
	canonical := CanonicalRequest("v1/1800", method, path, "", CanonicalHeaders(signedMap))
	sig, err := signMessage(suite, &privKey{rsa: b.platformPrivR, sm2: b.platformPrivS}, []byte(canonical), rnd)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(signedMap))
	for n := range signedMap {
		names = append(names, n)
	}
	sortStrings(names)
	h.Set(HeaderSign, buildSignHeader(suite.SecurityReq(), 1800, names, sig))
	return h, wire
}

func verifyClient(t *testing.T, suiteID string) *Client {
	t.Helper()
	c, err := NewClient(testConfig(t, suiteID))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyResponse_L0_L2_Happy(t *testing.T) {
	for _, suiteID := range []string{"WOP-RSA3072-SHA256", "WOP-RSA4096-SHA256", "WOP-SM2-SM3"} {
		b := newPlatformBuilder(t, suiteID)
		c := verifyClient(t, suiteID)

		h, wire := b.build(t, "POST", "/gateway/x", []byte(`{"code":"SUCCESS"}`), Level0, nil)
		res := c.VerifyResponse("POST", "/gateway/x", h, wire)
		if !res.OK || string(res.Plaintext) != `{"code":"SUCCESS"}` {
			t.Fatalf("%s L0: ok=%v code=%s reason=%s", suiteID, res.OK, res.Code, res.Reason)
		}

		h, wire = b.build(t, "POST", "/gateway/x", []byte(`{"secret":true}`), Level2, nil)
		res = c.VerifyResponse("POST", "/gateway/x", h, wire)
		if !res.OK || string(res.Plaintext) != `{"secret":true}` {
			t.Fatalf("%s L2: ok=%v code=%s reason=%s", suiteID, res.OK, res.Code, res.Reason)
		}
	}
}

func TestVerifyResponse_MissingSignHeader(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	h := http.Header{}
	res := c.VerifyResponse("POST", "/p", h, []byte("body"))
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("缺 sign 头: ok=%v code=%s", res.OK, res.Code)
	}
}

// I2：先验签后解密 —— 签名被篡改时返回验签模糊错误，绝不触碰解密路径。
func TestVerifyResponse_TamperedSignature_Fuzzy(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	h, wire := b.build(t, "POST", "/p", []byte(`{"secret":1}`), Level2, nil)
	sig := h.Get(HeaderSign)
	// 翻转签名末字符（b64url 字母表内替换）
	replaced := sig[:len(sig)-1] + string(rotB64u(sig[len(sig)-1]))
	h.Set(HeaderSign, replaced)

	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeVerifyFailed || res.Reason != verifyFuzzyMessage {
		t.Errorf("I2/I7: ok=%v code=%s reason=%q", res.OK, res.Code, res.Reason)
	}
}

// F6 顺序：验签 → digest 复核 —— 签名有效但 body 被篡改 → digest 错误（非解密错误）。
func TestVerifyResponse_TamperedBody_DigestMismatch(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-SM2-SM3")
	c := verifyClient(t, "WOP-SM2-SM3")
	h, wire := b.build(t, "POST", "/p", []byte(`{"a":1}`), Level2, nil)
	wire = append(append([]byte{}, wire...), 'x') // 中间人追加字节

	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeDigestMismatch {
		t.Errorf("F6: ok=%v code=%s（应先于解密失败暴露 digest 不匹配）", res.OK, res.Code)
	}
}

// I3：alg 族比对在 bulk 解密前 —— dek alg 与套件族不符 → 一致性类明确错误。
func TestVerifyResponse_AlgMismatchBeforeDecrypt(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-SM2-SM3")
	c := verifyClient(t, "WOP-SM2-SM3")
	// 构造：SM2 套件，但 DEK 声明 AES-256-GCM（跨族），密文为垃圾（若先解密必然失败）
	rnd := deterministicReader()
	suite := mustSuite(t, "WOP-SM2-SM3")
	wire := wrapEncryptedBody(EncodeB64URL([]byte("garbage-ciphertext-16b")))
	wrapped, err := wrapDEKPayload(suite, &pubKey{sm2: b.merchantPubS},
		[]byte(buildDekPayload("AES-256-GCM", readBytes(t, rnd, 32), readBytes(t, rnd, 12))), rnd)
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

	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeAlgMismatch {
		t.Errorf("I3: ok=%v code=%s reason=%s（应先于解密暴露族不符）", res.OK, res.Code, res.Reason)
	}
}

// F6 末段：GCM 解密失败（tag 不符）→ 模糊。
func TestVerifyResponse_GCMFailure_Fuzzy(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	// 平台签名密文被篡改后重算 digest 重签（digest 通过、解密必失败）
	h, wire := b.build(t, "POST", "/p", []byte(`{"a":1}`), Level2, func(hh *http.Header, w []byte) []byte {
		// 在 base64 载荷内原位替换字符（保持 JSON/b64url 合法，密文字节变化）
		w = append([]byte{}, w...)
		i := len(w) / 2
		if w[i] == 'A' {
			w[i] = 'B'
		} else {
			w[i] = 'A'
		}
		return w
	})
	// build 内 tamper 在 digest 计算前执行，digest/签名覆盖篡改后密文 → 全链合法但解密失败
	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeDecryptFailed || res.Reason != decryptFuzzyMessage {
		t.Errorf("F6/I7: ok=%v code=%s reason=%q", res.OK, res.Code, res.Reason)
	}
}

// DEK 解包失败（包装给错误商户）→ 模糊。
func TestVerifyResponse_DEKUnwrapFailure_Fuzzy(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-SM2-SM3")
	c := verifyClient(t, "WOP-SM2-SM3")
	other, _ := generateSM2KeyForTest()
	h, wire := b.build(t, "POST", "/p", []byte("x"), Level2, func(hh *http.Header, w []byte) []byte {
		// 用第三方公钥重包装 DEK（商户私钥解不开）
		suite := mustSuite(t, "WOP-SM2-SM3")
		rnd := deterministicReader()
		wrapped, err := wrapDEKPayload(suite, &pubKey{sm2: &other.PublicKey},
			[]byte(vDekPayloadSM2(t)), rnd)
		if err != nil {
			t.Fatal(err)
		}
		hh.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
		return w
	})
	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeDecryptFailed {
		t.Errorf("DEK 解包失败: ok=%v code=%s", res.OK, res.Code)
	}
}

// I1：digest 头存在且正确，但未列入 signedHeaders → 必须拒。
func TestVerifyResponse_DigestNotSigned_Reject(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	h, wire := b.build(t, "POST", "/p", []byte(`{"a":1}`), Level0, nil)
	parsed, err := ParseSignHeader(h.Get(HeaderSign))
	if err != nil {
		t.Fatal(err)
	}
	var without []string
	for _, name := range parsed.signedHeaders {
		if name != HeaderContentDigest {
			without = append(without, name)
		}
	}
	h.Set(HeaderSign, buildSignHeader(parsed.securityReq, parsed.expiredSeconds, without, parsed.signature))

	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("I1: ok=%v code=%s", res.OK, res.Code)
	}
}

// D2：有 body 缺 digest 头 → 拒；无 body 携带 digest → 拒。
func TestVerifyResponse_D2Rules(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")

	h, wire := b.build(t, "POST", "/p", []byte("body"), Level0, nil)
	h.Del(HeaderContentDigest)
	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeDigestMismatch {
		t.Errorf("缺 digest: ok=%v code=%s", res.OK, res.Code)
	}

	// 无 body：重新以空体签名（digest 不入签），再人为补 digest 头 → 拒
	h2, wire2 := b.build(t, "POST", "/p", nil, Level0, nil)
	h2.Set(HeaderContentDigest, DigestHeaderValue(mustSuite(t, "WOP-RSA3072-SHA256"), nil))
	res = c.VerifyResponse("POST", "/p", h2, wire2)
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("无 body 带 digest: ok=%v code=%s", res.OK, res.Code)
	}
}

func TestVerifyResponse_MiscProtocolErrors(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")

	// 响应套件与客户端配置不符（降级防护）
	h, wire := b.build(t, "POST", "/p", []byte("x"), Level0, nil)
	sig := h.Get(HeaderSign)
	h.Set(HeaderSign, "WOP-SM2-SM3"+sig[len("WOP-RSA3072-SHA256"):])
	res := c.VerifyResponse("POST", "/p", h, wire)
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("套件不符: ok=%v code=%s", res.OK, res.Code)
	}

	// 垃圾 securityReq（与配置不符即明确拒绝）
	h, _ = b.build(t, "POST", "/p", []byte("x"), Level0, nil)
	h.Set(HeaderSign, "GARBAGE "+h.Get(HeaderSign)[len("WOP-RSA3072-SHA256")+1:])
	res = c.VerifyResponse("POST", "/p", h, []byte("x"))
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("垃圾套件: ok=%v code=%s", res.OK, res.Code)
	}

	// signedHeaders 声明了缺失的头
	h, _ = b.build(t, "POST", "/p", []byte("x"), Level0, nil)
	parsed, _ := ParseSignHeader(h.Get(HeaderSign))
	h.Set(HeaderSign, buildSignHeader(parsed.securityReq, parsed.expiredSeconds,
		append(append([]string{}, parsed.signedHeaders...), "x-wop-missing"), parsed.signature))
	h.Del(HeaderNonce)
	res = c.VerifyResponse("POST", "/p", h, []byte("x"))
	if res.OK || res.Code != CodeProtocol {
		t.Errorf("缺失已签名头: ok=%v code=%s", res.OK, res.Code)
	}
}

func TestVerifyCallback_URLPathExtraction(t *testing.T) {
	b := newPlatformBuilder(t, "WOP-RSA3072-SHA256")
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	h, wire := b.build(t, "POST", "/callback/notify", []byte(`{"eventId":"e1"}`), Level2, nil)
	res := c.VerifyCallback("https://merchant.example.com/callback/notify?src=test", h, wire)
	if !res.OK || string(res.Plaintext) != `{"eventId":"e1"}` {
		t.Fatalf("callback: ok=%v code=%s reason=%s", res.OK, res.Code, res.Reason)
	}
	// 错误路径（canonical path 不符）→ 验签失败
	res = c.VerifyCallback("https://merchant.example.com/other/path", h, wire)
	if res.OK || res.Code != CodeVerifyFailed {
		t.Errorf("错误路径应验签失败: ok=%v code=%s", res.OK, res.Code)
	}
	// 非法回调 URL
	if res := c.VerifyCallback("://bad", h, wire); res.OK {
		t.Error("非法 callback URL 应拒绝")
	}
}

func rotB64u(c byte) byte {
	switch {
	case c == 'Z':
		return 'Y'
	case c >= 'a' && c <= 'z':
		return c - 1
	default:
		return byte('a' + (c % 25))
	}
}
