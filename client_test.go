package wop

import (
	"bytes"
	"io"
	"testing"
)

func testConfig(t *testing.T, suiteID string) Config {
	t.Helper()
	v := loadGoldenVectors(t)
	cfg := Config{
		AppKey:         "app_test_001",
		SecurityReq:    suiteID,
		GatewayBaseURL: "https://gw.example.com",
	}
	if suiteID == "WOP-SM2-SM3" {
		cfg.MerchantPrivateKey = v.Keys.SM2.PrivateDB64
		cfg.PlatformPublicKey = v.Keys.SM2.PublicPointB64
		return cfg
	}
	if suiteID == "WOP-RSA4096-SHA256" {
		cfg.MerchantPrivateKey = v.Keys.RSA4096.PrivatePkcs8B64
		cfg.PlatformPublicKey = v.Keys.RSA4096.PublicSpkiB64
		return cfg
	}
	cfg.MerchantPrivateKey = v.Keys.RSA3072.PrivatePkcs8B64
	cfg.PlatformPublicKey = v.Keys.RSA3072.PublicSpkiB64
	return cfg
}

func TestNewClient_ConfigValidation(t *testing.T) {
	valid := testConfig(t, "WOP-RSA3072-SHA256")

	if _, err := NewClient(valid); err != nil {
		t.Fatalf("合法配置不应失败: %v", err)
	}

	cases := []struct {
		name string
		mut  func(*Config)
		code ErrorCode
	}{
		{"空 appKey", func(c *Config) { c.AppKey = "" }, CodeConfig},
		{"空 securityReq", func(c *Config) { c.SecurityReq = "" }, CodeSuiteParse},
		{"非法套件", func(c *Config) { c.SecurityReq = "WOP-RSA3072-SM3" }, CodeSuiteUnsupported},
		{"空商户私钥", func(c *Config) { c.MerchantPrivateKey = "" }, CodeConfig},
		{"空平台公钥", func(c *Config) { c.PlatformPublicKey = "" }, CodeConfig},
		{"私钥垃圾", func(c *Config) { c.MerchantPrivateKey = "!!!" }, CodeConfig},
		{"expired 非法", func(c *Config) { c.ExpiredSeconds = -1 }, CodeConfig},
		{"expired 超上限", func(c *Config) { c.ExpiredSeconds = 86401 }, CodeConfig},
	}
	for _, tc := range cases {
		cfg := valid
		tc.mut(&cfg)
		_, err := NewClient(cfg)
		if err == nil {
			t.Errorf("%s: 应失败", tc.name)
			continue
		}
		we, ok := err.(*Error)
		if !ok {
			t.Errorf("%s: 错误类型 %T", tc.name, err)
			continue
		}
		if string(tc.code) != "" && we.Code != tc.code {
			t.Errorf("%s: 错误类 = %s, want %s", tc.name, we.Code, tc.code)
		}
	}

	// 密钥与套件族不符：RSA 套件配 SM2 私钥
	mismatch := valid
	mismatch.MerchantPrivateKey = loadGoldenVectors(t).Keys.SM2.PrivateDB64
	if _, err := NewClient(mismatch); err == nil {
		t.Error("族不匹配密钥应失败")
	}

	// RSA 位数不符：3072 套件配 4096 私钥
	bitMismatch := valid
	bitMismatch.MerchantPrivateKey = loadGoldenVectors(t).Keys.RSA4096.PrivatePkcs8B64
	if _, err := NewClient(bitMismatch); err == nil {
		t.Error("4096 私钥配 3072 套件应失败")
	}
}

func TestBuildRequest_L0(t *testing.T) {
	v := loadGoldenVectors(t)
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"waybillNo":"W202607200001"}`)
	draft, err := client.BuildRequest("POST", "/gateway/logistics.order.query", body, Level0,
		WithTimestamp(1755900000000), WithNonce("nonce-fixed-0001"))
	if err != nil {
		t.Fatal(err)
	}

	if draft.Method != "POST" {
		t.Errorf("Method = %q", draft.Method)
	}
	if !bytes.Equal(draft.WireBody, body) {
		t.Errorf("L0 wire body 应为原文")
	}
	for _, h := range []string{HeaderAppKey, HeaderTimestamp, HeaderNonce, HeaderContentDigest, HeaderSign} {
		if draft.Headers[h] == "" {
			t.Errorf("缺头 %s", h)
		}
	}
	if _, has := draft.Headers[HeaderEncrypt]; has {
		t.Error("L0 不应携带 x-wop-encrypt")
	}

	// D2/D3：digest 覆盖 wire body 且入 signedHeaders
	wantDigest := DigestHeaderValue(client.suite, body)
	if draft.Headers[HeaderContentDigest] != wantDigest {
		t.Errorf("digest = %q, want %q", draft.Headers[HeaderContentDigest], wantDigest)
	}
	parsed, err := ParseSignHeader(draft.Headers[HeaderSign])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.securityReq != "WOP-RSA3072-SHA256" || parsed.expiredSeconds != 1800 {
		t.Errorf("sign 头段: %+v", parsed)
	}
	wantSigned := []string{HeaderAppKey, HeaderContentDigest, HeaderNonce, HeaderTimestamp}
	if len(parsed.signedHeaders) != len(wantSigned) {
		t.Fatalf("signedHeaders = %v", parsed.signedHeaders)
	}
	for i := range wantSigned {
		if parsed.signedHeaders[i] != wantSigned[i] {
			t.Fatalf("signedHeaders = %v, want %v", parsed.signedHeaders, wantSigned)
		}
	}

	// 商户公钥验签（回环）
	pub := &pubKey{}
	if pub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
		t.Fatal(err)
	}
	signedMap := map[string]string{}
	for _, h := range parsed.signedHeaders {
		signedMap[h] = draft.Headers[h]
	}
	canonical := CanonicalRequest(parsed.authString(), "POST", "/gateway/logistics.order.query", "",
		CanonicalHeaders(signedMap))
	if err := verifyMessage(client.suite, pub, []byte(canonical), parsed.signature); err != nil {
		t.Fatalf("回环验签失败: %v", err)
	}
}

func TestBuildRequest_L0_NoBody(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	draft, err := client.BuildRequest("GET", "/gateway/x", nil, Level0,
		WithTimestamp(1755900000000), WithNonce("n2"))
	if err != nil {
		t.Fatal(err)
	}
	if draft.WireBody != nil && len(draft.WireBody) > 0 {
		t.Error("GET wire body 应为空")
	}
	if _, has := draft.Headers[HeaderContentDigest]; has {
		t.Error("无 body → digest 头必须缺席（D2）")
	}
	parsed, _ := ParseSignHeader(draft.Headers[HeaderSign])
	for _, h := range parsed.signedHeaders {
		if h == HeaderContentDigest {
			t.Error("无 body → digest 不入 signedHeaders（I1 不适用即缺席）")
		}
	}
}

func TestBuildRequest_L2(t *testing.T) {
	v := loadGoldenVectors(t)
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"secret":"payload"}`)
	draft, err := client.BuildRequest("POST", "/gateway/secure.api", plain, Level2,
		WithTimestamp(1755900000000), WithNonce("n3"))
	if err != nil {
		t.Fatal(err)
	}

	// wire body 是信封，不泄漏明文
	if bytes.Contains(draft.WireBody, plain) {
		t.Fatal("L2 wire body 泄漏明文")
	}
	if string(draft.WireBody)[:1] != "{" {
		t.Errorf("wire body 不是 JSON 信封: %s", draft.WireBody)
	}
	if draft.Headers[HeaderEncrypt] == "" {
		t.Fatal("L2 必须携带 x-wop-encrypt")
	}
	// digest 覆盖密文载体（D2：摘要对象 = 线上原始字节）
	if draft.Headers[HeaderContentDigest] != DigestHeaderValue(client.suite, draft.WireBody) {
		t.Error("digest 须覆盖密文 wire body")
	}

	// 平台侧回环解密：解包 DEK（平台私钥）→ alg 校验 → 解密
	_, dekB64u, err := parseEncryptHeader(draft.Headers[HeaderEncrypt])
	if err != nil {
		t.Fatal(err)
	}
	platformPriv := &privKey{}
	if platformPriv.rsa, err = parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64); err != nil {
		t.Fatal(err)
	}
	payloadPlain, err := unwrapDEKPayload(client.suite, platformPriv, dekB64u)
	if err != nil {
		t.Fatalf("平台解包 DEK: %v", err)
	}
	payload, err := parseDekPayload(string(payloadPlain))
	if err != nil {
		t.Fatal(err)
	}
	if payload.alg != "AES-256-GCM" {
		t.Errorf("dek alg = %q", payload.alg)
	}
	cipherB64u, err := extractEncryptedBody(draft.WireBody)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openMessage(client.suite, mustDecodeB64u(t, cipherB64u), payload.key, payload.iv)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("L2 回环解密: %v", err)
	}

	// L2 signedHeaders 含 x-wop-encrypt
	parsed, _ := ParseSignHeader(draft.Headers[HeaderSign])
	found := false
	for _, h := range parsed.signedHeaders {
		if h == HeaderEncrypt {
			found = true
		}
	}
	if !found {
		t.Error("L2 signedHeaders 须含 x-wop-encrypt")
	}
}

// 幂等重放：同 timestamp/nonce/随机源 → 字节级一致（spec §2 确定性要求）。
func TestBuildRequest_DeterministicReplay(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	fixed := func() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0xAB}, 256)) }
	body := []byte(`{"k":1}`)

	d1, err := client.BuildRequest("POST", "/p", body, Level2,
		WithTimestamp(1755900000000), WithNonce("n4"), WithRandom(fixed()))
	if err != nil {
		t.Fatal(err)
	}
	d2, err := client.BuildRequest("POST", "/p", body, Level2,
		WithTimestamp(1755900000000), WithNonce("n4"), WithRandom(fixed()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d1.WireBody, d2.WireBody) {
		t.Error("同随机源 wire body 应字节一致")
	}
	if d1.Headers[HeaderSign] != d2.Headers[HeaderSign] {
		t.Error("同随机源签名应一致")
	}
	if d1.Headers[HeaderEncrypt] != d2.Headers[HeaderEncrypt] {
		t.Error("同随机源 encrypt 头应一致")
	}
}

func TestBuildRequest_SM2Suite(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-SM2-SM3"))
	if err != nil {
		t.Fatal(err)
	}
	draft, err := client.BuildRequest("POST", "/p", []byte("中文 payload"), Level2,
		WithTimestamp(1755900000000), WithNonce("n5"))
	if err != nil {
		t.Fatal(err)
	}
	if client.suite.DigestTag() != "sm3" {
		t.Fatalf("SM2 套件 digest tag = %q", client.suite.DigestTag())
	}
	if len(draft.Headers[HeaderContentDigest]) != len("sm3 ")+64 {
		t.Errorf("sm3 digest 头格式: %q", draft.Headers[HeaderContentDigest])
	}
	// 平台回环：SM2 DEK 解包
	_, dekB64u, _ := parseEncryptHeader(draft.Headers[HeaderEncrypt])
	priv := &privKey{sm2: mustSM2Priv(t, loadGoldenVectors(t).Keys.SM2.PrivateDB64)}
	payloadPlain, err := unwrapDEKPayload(client.suite, priv, dekB64u)
	if err != nil {
		t.Fatalf("SM2 DEK 解包: %v", err)
	}
	payload, err := parseDekPayload(string(payloadPlain))
	if err != nil || payload.alg != "SM4-GCM" {
		t.Fatalf("SM2 dek alg = %q err=%v", payload.alg, err)
	}
	cipherB64u, _ := extractEncryptedBody(draft.WireBody)
	got, err := openMessage(client.suite, mustDecodeB64u(t, cipherB64u), payload.key, payload.iv)
	if err != nil || string(got) != "中文 payload" {
		t.Fatalf("SM2 L2 回环: %v", err)
	}
}

func TestBuildRequest_ParamErrors(t *testing.T) {
	client, _ := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if _, err := client.BuildRequest("", "/p", nil, Level0); err == nil {
		t.Error("空 method 应拒绝")
	}
	if _, err := client.BuildRequest("POST", "", nil, Level0); err == nil {
		t.Error("空 path 应拒绝")
	}
	if _, err := client.BuildRequest("POST", "/p", nil, "L9"); err == nil {
		t.Error("未知加密级别应拒绝")
	}
}

func TestBuildRequest_ExpiredSecondsConfig(t *testing.T) {
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.ExpiredSeconds = 600
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := client.BuildRequest("POST", "/p", []byte("b"), Level0,
		WithTimestamp(1), WithNonce("n"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := ParseSignHeader(draft.Headers[HeaderSign])
	if parsed.expiredSeconds != 600 {
		t.Errorf("expiredSeconds = %d, want 600", parsed.expiredSeconds)
	}
}
