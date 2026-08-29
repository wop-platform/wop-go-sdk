package wop

// spec:A6/D2/I1/I2/I3/I7/F1-F9 Gherkin/godog 验收套件：features/wop_gateway.feature。
// 入向场景的"平台响应"由独立网关模拟器拼装（D5 纪律：不经被测
// 出向代码 BuildRequest 镜像构造）；平台侧复核走商户公钥/私钥原语。
// step 断言一律返回 error（godog 惯例），禁止在 step 内 Fatal/Goexit。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

type bddState struct {
	t          *testing.T
	suiteID    string
	cfg        Config
	client     *Client
	builder    *platformResponseBuilder
	respSuite  string // 平台模拟器实际使用的套件（响应套件不符场景）
	drafts     []RequestDraft
	respHeader http.Header
	respBody   []byte
	path       string
	result     VerifyResult
	err        error
	captured   *RequestDraft
}

func TestFeatures(t *testing.T) {
	s := &bddState{t: t}
	suite := godog.TestSuite{
		ScenarioInitializer: s.registerSteps,
		Options: &godog.Options{
			Format:   "progress",
			Paths:    []string{"features"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog feature 场景未全部通过")
	}
}

func (s *bddState) registerSteps(ctx *godog.ScenarioContext) {
	ctx.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		s.builder = nil
		s.respSuite = ""
		s.drafts = nil
		s.captured = nil
		s.err = nil
		s.result = VerifyResult{}
		s.cfg = Config{}
		return ctx, nil
	})
	// ---------- 背景 ----------

	ctx.Given(`^黄金向量 fixture 已加载$`, func() error {
		v := loadGoldenVectors(s.t)
		if v.Inputs.Message == "" || v.Keys.RSA3072.PrivatePkcs8B64 == "" {
			return fmt.Errorf("黄金向量 fixture 关键字段缺失")
		}
		return nil
	})

	// ---------- S1 配置（F1） ----------

	ctx.Given(`^商户准备 WOP-(RSA3072|RSA4096|SM2)-SHA256 套件的密钥材料$`, func(alg string) {
		s.cfg = testConfig(s.t, "WOP-"+alg+"-SHA256")
	})
	ctx.Given(`^商户准备 WOP-SM2-SM3 套件的密钥材料$`, func() {
		s.cfg = testConfig(s.t, "WOP-SM2-SM3")
	})
	ctx.Given(`^商户准备跨族套件标识 (.+)$`, func(id string) {
		s.cfg = testConfig(s.t, "WOP-RSA3072-SHA256")
		s.cfg.SecurityReq = id
	})
	ctx.Given(`^商户准备非法格式套件标识 (.+)$`, func(id string) {
		s.cfg = testConfig(s.t, "WOP-RSA3072-SHA256")
		s.cfg.SecurityReq = id
	})
	ctx.When(`^商户创建 WopClient$`, func() {
		s.client, s.err = NewClient(s.cfg)
	})
	ctx.Then(`^配置成功$`, func() error {
		if s.err != nil {
			return fmt.Errorf("配置应成功，实际: %v", s.err)
		}
		return nil
	})
	ctx.Then(`^套件摘要标签为 (\S+)$`, func(tag string) error {
		if got := s.client.Suite().DigestTag(); got != tag {
			return fmt.Errorf("DigestTag = %q, want %q", got, tag)
		}
		return nil
	})
	ctx.Then(`^套件报文算法为 (\S+)$`, func(alg string) error {
		if got := s.client.Suite().MessageAlgorithm(); got != alg {
			return fmt.Errorf("MessageAlgorithm = %q, want %q", got, alg)
		}
		return nil
	})
	ctx.Then(`^配置失败，错误码为 (\S+)$`, func(code string) error {
		if s.err == nil {
			return fmt.Errorf("配置应失败")
		}
		we, ok := s.err.(*Error)
		if !ok {
			return fmt.Errorf("错误应为 *Error，实际 %T", s.err)
		}
		if string(we.Code) != code {
			return fmt.Errorf("错误码 = %q, want %q（%s）", we.Code, code, we.Message)
		}
		return nil
	})

	// ---------- 客户端就绪 ----------

	ctx.Given(`^商户已创建 WOP-RSA3072-SHA256 客户端$`, func() error {
		c, err := NewClient(testConfig(s.t, "WOP-RSA3072-SHA256"))
		if err != nil {
			return err
		}
		s.client, s.suiteID = c, "WOP-RSA3072-SHA256"
		s.builder = newPlatformBuilder(s.t, "WOP-RSA3072-SHA256")
		return nil
	})
	ctx.Given(`^商户已创建 WOP-RSA4096-SHA256 客户端$`, func() error {
		c, err := NewClient(testConfig(s.t, "WOP-RSA4096-SHA256"))
		if err != nil {
			return err
		}
		s.client, s.suiteID = c, "WOP-RSA4096-SHA256"
		s.builder = newPlatformBuilder(s.t, "WOP-RSA4096-SHA256")
		return nil
	})
	ctx.Given(`^商户已创建 WOP-SM2-SM3 客户端$`, func() error {
		c, err := NewClient(testConfig(s.t, "WOP-SM2-SM3"))
		if err != nil {
			return err
		}
		s.client, s.suiteID = c, "WOP-SM2-SM3"
		s.builder = newPlatformBuilder(s.t, "WOP-SM2-SM3")
		return nil
	})

	// ---------- S2 出向 L0（F2/F3/F4/F9） ----------

	buildOpts := func() []RequestOption {
		return []RequestOption{WithTimestamp(1755900000000), WithNonce("bdd-nonce-0001")}
	}
	ctx.When(`^商户以固定时间戳与 nonce 构建 L0 (\S+) (\S+) 请求，报文为 (.+)$`,
		func(method, path, body string) error {
			d, err := s.client.BuildRequest(method, path, []byte(body), Level0, buildOpts()...)
			s.drafts = append(s.drafts, d)
			s.err = err
			return nil
		})
	ctx.When(`^商户以固定时间戳与 nonce 构建 L0 (\S+) (\S+) 请求，无报文$`,
		func(method, path string) error {
			d, err := s.client.BuildRequest(method, path, nil, Level0, buildOpts()...)
			s.drafts = append(s.drafts, d)
			s.err = err
			return nil
		})
	ctx.Then(`^请求草稿携带头 (\S+) 与 (\S+) 与 (\S+)$`, func(h1, h2, h3 string) error {
		d := s.lastDraft()
		for _, h := range []string{h1, h2, h3} {
			if d.Headers[h] == "" {
				return fmt.Errorf("请求草稿缺少头 %s", h)
			}
		}
		return nil
	})
	ctx.Then(`^x-wop-content-digest 以 "(.+)" 开头且为 64 位小写 hex$`, func(prefix string) error {
		v := s.lastDraft().Headers[HeaderContentDigest]
		tag, hexSum, err := ParseContentDigest(v)
		if err != nil {
			return fmt.Errorf("digest 头 %q 非法: %v", v, err)
		}
		if !strings.HasPrefix(v, prefix+" ") || tag != prefix ||
			len(hexSum) != 64 || strings.ToLower(hexSum) != hexSum {
			return fmt.Errorf("digest 头 %q 不符预期（tag=%s）", v, tag)
		}
		return nil
	})
	ctx.Then(`^平台以商户公钥对 canonicalRequest 验签通过$`, func() error {
		return platformVerifyDraft(s.t, s.suiteID, s.lastDraft())
	})
	ctx.Then(`^请求草稿不携带 x-wop-content-digest$`, func() error {
		if _, ok := s.lastDraft().Headers[HeaderContentDigest]; ok {
			return fmt.Errorf("无报文请求不应携带 digest 头")
		}
		return nil
	})
	ctx.Then(`^签名头不含 x-wop-content-digest$`, func() error {
		d := s.lastDraft()
		parsed, err := ParseSignHeader(d.Headers[HeaderSign])
		if err != nil {
			return err
		}
		if containsHeader(parsed.signedHeaders, HeaderContentDigest) {
			return fmt.Errorf("无报文请求的 signedHeaders 不应含 digest")
		}
		return nil
	})

	// ---------- S2 确定性重放 ----------

	ctx.When(`^商户以固定时间戳、nonce 与随机源两次构建同一 L2 请求$`, func() error {
		opts := func() []RequestOption {
			return []RequestOption{
				WithTimestamp(1755900000000), WithNonce("bdd-nonce-replay"),
				WithRandom(deterministicReader()),
			}
		}
		d1, err1 := s.client.BuildRequest("POST", "/gateway/x", []byte(`{"r":1}`), Level2, opts()...)
		d2, err2 := s.client.BuildRequest("POST", "/gateway/x", []byte(`{"r":1}`), Level2, opts()...)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("构建失败: %v / %v", err1, err2)
		}
		s.drafts = append(s.drafts, d1, d2)
		return nil
	})
	ctx.Then(`^两次请求草稿的字节输出完全一致$`, func() error {
		a, b := s.drafts[len(s.drafts)-2], s.drafts[len(s.drafts)-1]
		if !bytes.Equal(a.WireBody, b.WireBody) {
			return fmt.Errorf("两次构建的 wireBody 不一致")
		}
		if fmt.Sprint(a.Headers) != fmt.Sprint(b.Headers) {
			return fmt.Errorf("两次构建的 headers 不一致")
		}
		return nil
	})

	// ---------- S3 出向 L2（F5） ----------

	ctx.When(`^商户以固定随机源构建 L2 (\S+) (\S+) 请求，报文为 (.+)$`,
		func(method, path, body string) error {
			d, err := s.client.BuildRequest(method, path, []byte(body), Level2,
				WithTimestamp(1755900000000), WithNonce("bdd-nonce-l2"), WithRandom(deterministicReader()))
			s.drafts = append(s.drafts, d)
			s.err = err
			return nil
		})
	ctx.Then(`^请求草稿携带 x-wop-encrypt 头，格式为 L2;dek=<base64url>$`, func() error {
		v := s.lastDraft().Headers[HeaderEncrypt]
		level, dek, err := parseEncryptHeader(v)
		if err != nil || level != "L2" || !isStrictB64URLChars(dek) {
			return fmt.Errorf("x-wop-encrypt 头非法: %q（%v）", v, err)
		}
		return nil
	})
	ctx.Then(`^请求体为 \{"encrypted":"<base64url>"\} JSON 信封$`, func() error {
		var env map[string]any
		if err := json.Unmarshal(s.lastDraft().WireBody, &env); err != nil {
			return fmt.Errorf("信封不是 JSON: %v", err)
		}
		if _, ok := env["encrypted"]; !ok {
			return fmt.Errorf("信封缺少 encrypted 字段")
		}
		return nil
	})
	ctx.Then(`^平台以商户私钥解包 DEK 后可解密还原明文$`, func() error {
		return platformOpenDraft(s.t, s.suiteID, s.lastDraft())
	})
	ctx.Then(`^平台解包后 SM4-GCM 明文与原文一致$`, func() error {
		plain, err := platformOpenDraftPlain(s.t, s.suiteID, s.lastDraft())
		if err != nil {
			return err
		}
		if string(plain) != `{"g":"m"}` {
			return fmt.Errorf("SM2 L2 明文不符: %q", plain)
		}
		return nil
	})

	// ---------- S4/S5 入向校验（F6） ----------

	ctx.Given(`^平台模拟器产出 L0 响应，路径 (\S+)，明文 (.+)$`, func(path, plaintext string) {
		s.path = path
		s.respHeader, s.respBody = s.builder.build(s.t, "POST", path, []byte(plaintext), Level0, nil)
	})
	ctx.Given(`^平台模拟器产出 L2 响应，路径 (\S+)，明文 (.+)$`, func(path, plaintext string) {
		s.path = path
		s.respHeader, s.respBody = s.builder.build(s.t, "POST", path, []byte(plaintext), Level2, nil)
	})
	ctx.Given(`^平台模拟器产出 L0 回调，回调地址 (\S+)，明文 (.+)$`, func(callbackURL, plaintext string) {
		s.path = callbackURL
		s.respHeader, s.respBody = s.builder.build(s.t, "POST", "/wop/callback", []byte(plaintext), Level0, nil)
	})
	ctx.Given(`^平台模拟器以 WOP-RSA3072-SHA256 套件产出 L0 响应，路径 (\S+)，明文 (.+)$`,
		func(path, plaintext string) {
			s.path = path
			b := newPlatformBuilder(s.t, "WOP-RSA3072-SHA256")
			s.respHeader, s.respBody = b.build(s.t, "POST", path, []byte(plaintext), Level0, nil)
		})
	ctx.Given(`^平台模拟器产出 alg 跨族的 L2 响应，路径 (\S+)，明文 (.+)$`, func(path, plaintext string) {
		s.path = path
		s.respHeader, s.respBody = bddCrossFamilyL2(s.t, s.builder, path, []byte(plaintext))
	})

	ctx.When(`^商户校验响应$`, func() {
		s.result = s.client.VerifyResponse("POST", s.path, s.respHeader, s.respBody)
	})
	ctx.When(`^商户校验回调$`, func() {
		s.result = s.client.VerifyCallback(s.path, s.respHeader, s.respBody)
	})
	ctx.Then(`^校验通过且明文为 (.+)$`, func(plaintext string) error {
		if !s.result.OK {
			return fmt.Errorf("校验应通过: code=%s reason=%s", s.result.Code, s.result.Reason)
		}
		if string(s.result.Plaintext) != plaintext {
			return fmt.Errorf("明文 = %q, want %q", s.result.Plaintext, plaintext)
		}
		return nil
	})

	// ---------- S4 负向（D2/I2/I3/I7/F7） ----------

	ctx.Given(`^中间人篡改响应体一个字节$`, func() error {
		if len(s.respBody) == 0 {
			return fmt.Errorf("无响应体可篡改")
		}
		s.respBody[0] ^= 0x01
		return nil
	})
	ctx.Given(`^中间人替换签名为另一条合法签名$`, func() error {
		suite := mustSuite(s.t, s.respSuiteOf())
		h := s.respHeader
		signedMap := map[string]string{}
		parsed, err := ParseSignHeader(h.Get(HeaderSign))
		if err != nil {
			return err
		}
		for _, name := range parsed.signedHeaders {
			signedMap[name] = h.Get(name)
		}
		// 对不同 canonical（URI 换路径）签名：结构合法但与被验内容不符
		canonical := CanonicalRequest(parsed.authString(), "POST", "/other/path", "", CanonicalHeaders(signedMap))
		sig, err := signMessage(suite, &privKey{rsa: s.builder.platformPrivR, sm2: s.builder.platformPrivS},
			[]byte(canonical), deterministicReader())
		if err != nil {
			return err
		}
		h.Set(HeaderSign, buildSignHeader(suite.SecurityReq(), parsed.expiredSeconds, parsed.signedHeaders, sig))
		return nil
	})
	ctx.Given(`^中间人在签名末尾追加 =$`, func() {
		h := s.respHeader
		h.Set(HeaderSign, h.Get(HeaderSign)+"=")
	})
	ctx.Given(`^平台模拟器产出 DEK 密钥错误的 L2 响应，路径 (\S+)，明文 (.+)$`,
		func(path, plaintext string) {
			s.path = path
			s.respHeader, s.respBody = bddWrongKeyL2(s.t, s.builder, path, []byte(plaintext))
		})

	ctx.Then(`^校验失败，错误码为 (\S+)$`, func(code string) error {
		if s.result.OK {
			return fmt.Errorf("校验应失败（code=%s）", code)
		}
		if string(s.result.Code) != code {
			return fmt.Errorf("错误码 = %q, want %q（reason=%s）", s.result.Code, code, s.result.Reason)
		}
		return nil
	})
	ctx.Then(`^错误文案为固定模糊文案 "(.+)"$`, func(msg string) error {
		if s.result.Reason != msg {
			return fmt.Errorf("文案 = %q, want 固定模糊文案 %q", s.result.Reason, msg)
		}
		return nil
	})

	// ---------- S6 一站式 Do ----------

	ctx.Given(`^网关 Transport 被注入为模拟网关$`, func() error {
		s.captured = &RequestDraft{}
		cfg := s.cfg
		if cfg.AppKey == "" {
			cfg = testConfig(s.t, "WOP-RSA3072-SHA256")
		}
		cfg.Transport = TransportFunc(func(d RequestDraft) (TransportResponse, error) {
			*s.captured = d
			return TransportResponse{StatusCode: 200, Headers: s.respHeader, Body: s.respBody}, nil
		})
		c, err := NewClient(cfg)
		if err != nil {
			return err
		}
		s.client = c
		return nil
	})
	ctx.When(`^商户以固定随机源发起 Do (\S+) (\S+) L2 调用$`, func(method, path string) {
		s.result, _, s.err = s.client.Do(method, path, []byte(`{"do":1}`), Level2,
			WithTimestamp(1755900000000), WithNonce("bdd-nonce-do"), WithRandom(deterministicReader()))
	})
	ctx.Then(`^调用成功且明文为 (.+)$`, func(plaintext string) error {
		if s.err != nil {
			return fmt.Errorf("Do 调用应成功: %v", s.err)
		}
		if !s.result.OK || string(s.result.Plaintext) != plaintext {
			return fmt.Errorf("Do 结果 ok=%v plain=%q reason=%s",
				s.result.OK, s.result.Plaintext, s.result.Reason)
		}
		return nil
	})
	ctx.Then(`^模拟网关收到的请求可被平台侧完整校验$`, func() error {
		if err := platformVerifyDraft(s.t, s.suiteID, *s.captured); err != nil {
			return fmt.Errorf("平台侧验签失败: %w", err)
		}
		if err := platformOpenDraft(s.t, s.suiteID, *s.captured); err != nil {
			return fmt.Errorf("平台侧解密失败: %w", err)
		}
		return nil
	})
}

func (s *bddState) lastDraft() RequestDraft {
	if len(s.drafts) == 0 {
		s.t.Fatal("无请求草稿")
	}
	return s.drafts[len(s.drafts)-1]
}

func (s *bddState) respSuiteOf() string {
	if s.respSuite != "" {
		return s.respSuite
	}
	return s.suiteID
}

// platformVerifyDraft 平台侧复核出向请求：解析签名头 → 重建 canonical → 商户公钥验签。
func platformVerifyDraft(t *testing.T, suiteID string, d RequestDraft) error {
	t.Helper()
	suite := mustSuite(t, suiteID)
	parsed, err := ParseSignHeader(d.Headers[HeaderSign])
	if err != nil {
		return fmt.Errorf("签名头: %w", err)
	}
	if parsed.securityReq != suiteID {
		return fmt.Errorf("套件不符: %s", parsed.securityReq)
	}
	signedMap := map[string]string{}
	for _, name := range parsed.signedHeaders {
		signedMap[name] = d.Headers[name]
	}
	canonical := CanonicalRequest(parsed.authString(), d.Method, d.Path, "", CanonicalHeaders(signedMap))

	v := loadGoldenVectors(t)
	platformPub := &pubKey{}
	if suite.IsSM2() {
		platformPub.sm2 = mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
	} else {
		if platformPub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
			return err
		}
	}
	if err := verifyMessage(suite, platformPub, []byte(canonical), parsed.signature); err != nil {
		return fmt.Errorf("验签: %w", err)
	}
	if len(d.WireBody) > 0 {
		if err := ValidateContentDigest(suite, d.Headers[HeaderContentDigest], d.WireBody); err != nil {
			return fmt.Errorf("digest: %w", err)
		}
	}
	return nil
}

// platformOpenDraft 平台侧 L2 解密：解包 DEK → 解析载荷 → bulk 解密。
func platformOpenDraft(t *testing.T, suiteID string, d RequestDraft) error {
	t.Helper()
	_, err := platformOpenDraftPlain(t, suiteID, d)
	return err
}

func platformOpenDraftPlain(t *testing.T, suiteID string, d RequestDraft) ([]byte, error) {
	t.Helper()
	suite := mustSuite(t, suiteID)
	level, dekB64u, err := parseEncryptHeader(d.Headers[HeaderEncrypt])
	if err != nil {
		return nil, err
	}
	if level != "L2" {
		return nil, fmt.Errorf("level = %s", level)
	}
	v := loadGoldenVectors(t)
	merchantPriv := &privKey{}
	if suite.IsSM2() {
		merchantPriv.sm2 = mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	} else {
		if merchantPriv.rsa, err = parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64); err != nil {
			return nil, err
		}
	}
	payloadPlain, err := unwrapDEKPayload(suite, merchantPriv, dekB64u)
	if err != nil {
		return nil, fmt.Errorf("DEK 解包: %w", err)
	}
	payload, err := parseDekPayload(string(payloadPlain))
	if err != nil {
		return nil, err
	}
	cipherB64u, err := extractEncryptedBody(d.WireBody)
	if err != nil {
		return nil, err
	}
	ciphertext, err := DecodeB64URL(cipherB64u)
	if err != nil {
		return nil, err
	}
	return openMessage(suite, ciphertext, payload.key, payload.iv)
}

// bddCrossFamilyL2 构造 alg 跨族 L2 响应（D5：独立拼装，不经 BuildRequest）：
// 报文用 SM4-GCM（key/iv 16B/12B），DEK 载荷 alg 段写 SM4-GCM，
// 但 DEK 包装仍用商户 RSA 公钥（使解包成功、在 alg 比对处被拒）。
func bddCrossFamilyL2(t *testing.T, b *platformResponseBuilder, path string, plaintext []byte) (http.Header, []byte) {
	t.Helper()
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	rnd := deterministicReader()

	sm4Key := readBytes(t, rnd, 16)
	iv := readBytes(t, rnd, gcmIVLen)
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	ct, err := sealMessage(sm2Suite, plaintext, sm4Key, iv) // SM4-GCM 加密
	if err != nil {
		t.Fatal(err)
	}
	wire := wrapEncryptedBody(EncodeB64URL(ct))

	h := http.Header{}
	h.Set(HeaderNonce, "resp-nonce-cross")
	h.Set(HeaderTimestamp, strconv.FormatInt(1755900000000, 10))
	h.Set(HeaderContentDigest, DigestHeaderValue(rsaSuite, wire))

	// DEK 载荷 alg 故意写 SM4-GCM（与客户端 RSA 族不符）
	wrapped, err := wrapDEKPayload(rsaSuite, &pubKey{rsa: b.merchantPubR},
		[]byte("SM4-GCM$"+EncodeB64URL(sm4Key)+"$"+EncodeB64URL(iv)), rnd)
	if err != nil {
		t.Fatal(err)
	}
	h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))

	signedMap := map[string]string{}
	for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
		signedMap[name] = h.Get(name)
	}
	canonical := CanonicalRequest("v1/1800", "POST", path, "", CanonicalHeaders(signedMap))
	sig, err := signMessage(rsaSuite, &privKey{rsa: b.platformPrivR}, []byte(canonical), rnd)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(signedMap))
	for n := range signedMap {
		names = append(names, n)
	}
	sortStrings(names)
	h.Set(HeaderSign, buildSignHeader(rsaSuite.SecurityReq(), 1800, names, sig))
	return h, wire
}

// bddWrongKeyL2 构造"验签与 digest 均合法、但 DEK 载荷密钥与加密密钥不符"的
// L2 响应（D5：独立拼装）。失败精确落在 F6 管线 bulk 解密步（GCM tag 校验），
// 触发 I7 模糊文案。
func bddWrongKeyL2(t *testing.T, b *platformResponseBuilder, path string, plaintext []byte) (http.Header, []byte) {
	t.Helper()
	suite := mustSuite(t, "WOP-RSA3072-SHA256")
	rnd := deterministicReader()

	encryptKey := readBytes(t, rnd, suite.cekLen()) // 真实加密密钥
	dekKey := readBytes(t, rnd, suite.cekLen())     // 载荷里的错误密钥
	dekKey[0] ^= 0xFF                               // 同源 reader 读出的两段相同，显式分化确保密钥不符
	iv := readBytes(t, rnd, gcmIVLen)
	ct, err := sealMessage(suite, plaintext, encryptKey, iv)
	if err != nil {
		t.Fatal(err)
	}
	wire := wrapEncryptedBody(EncodeB64URL(ct))

	h := http.Header{}
	h.Set(HeaderNonce, "resp-nonce-wrongkey")
	h.Set(HeaderTimestamp, "1755900000000")
	h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
	wrapped, err := wrapDEKPayload(suite, &pubKey{rsa: b.merchantPubR},
		[]byte(buildDekPayload(suite.MessageAlgorithm(), dekKey, iv)), rnd)
	if err != nil {
		t.Fatal(err)
	}
	h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))

	signedMap := map[string]string{}
	for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
		signedMap[name] = h.Get(name)
	}
	canonical := CanonicalRequest("v1/1800", "POST", path, "", CanonicalHeaders(signedMap))
	sig, err := signMessage(suite, &privKey{rsa: b.platformPrivR}, []byte(canonical), rnd)
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
