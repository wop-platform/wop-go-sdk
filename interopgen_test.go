package wop

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/big"
	"net/http"
	"os"
	"testing"

	"bytes"
)

// interop 样本集生成器（协议编排跨仓一致性合同，wop-specs/interop/v1）。
// 重新生成：UPDATE_INTEROP=1 go test -run TestInteropGenerate ./...
// 纪律：fixture 与消费测试（interop_test.go）同走 CI；样本字节冻结禁手改，
// 变更必须经重新生成并六仓同步拷贝。

type interopCase struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"` // build | verify-positive | verify-negative
	Suite string `json:"suite,omitempty"`
	Level string `json:"level,omitempty"`

	// build 方向：同输入必须复现同 draft
	Input *interopBuildInput `json:"input,omitempty"`
	// build 期望（reproduceMode: byte-exact | deterministic-fields）
	Expected *interopBuildExpected `json:"expected,omitempty"`

	// verify 方向：样本即数据，消费仓不重新生成
	Response   *interopResponse `json:"response,omitempty"`
	VerifyPath string           `json:"verifyPath,omitempty"` // 覆盖校验路径（重放用例）
	Expect     *interopExpect   `json:"expect,omitempty"`
}

type interopBuildInput struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	AppKey       string `json:"appKey"`
	PlaintextB64 string `json:"plaintextB64"`
	TimestampMs  int64  `json:"timestampMs"`
	Nonce        string `json:"nonce"`
	RandomHex    string `json:"randomHex"` // 消费顺序合同：[16B nonce 池][CEK][IV][k…]（k 段各仓实现自定义）
}

type interopBuildExpected struct {
	ReproduceMode string            `json:"reproduceMode"` // byte-exact | deterministic-fields
	WireBodyB64   string            `json:"wireBodyB64"`
	Headers       map[string]string `json:"headers"`          // deterministic-fields 模式下 opaque 字段已按规则剥离
	Opaque        []string          `json:"opaque,omitempty"` // 不参与字节比对的字段：x-wop-sign.signatureSegment / x-wop-encrypt.dekValue
}

type interopResponse struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	AppKey      string            `json:"appKey"`
	Headers     map[string]string `json:"headers"`
	WireBodyB64 string            `json:"wireBodyB64"`
}

type interopExpect struct {
	OK           bool   `json:"ok"`
	PlaintextB64 string `json:"plaintextB64,omitempty"`
	ErrorClass   string `json:"errorClass,omitempty"` // ok|verify-failed|decrypt-failed|digest-mismatch|protocol|alg-mismatch
	Description  string `json:"description,omitempty"`
}

type interopFixture struct {
	Meta struct {
		Format      string `json:"format"`
		SpecVersion string `json:"specVersion"`
		GeneratedBy string `json:"generatedBy"`
		CaseCount   int    `json:"caseCount"`
		Note        string `json:"note"`
	} `json:"_meta"`
	Cases []interopCase `json:"cases"`
}

const (
	interopAppKey = "app_interop_001"
	interopPath   = "/gateway/interop.echo"
	interopPlain  = `{"k":"interop","n":1}`
)

func interopRandomHex(seed string) string {
	h := fnv.New128a()
	h.Write([]byte(seed))
	out := make([]byte, 0, 512)
	for len(out) < 512 {
		out = h.Sum(out[:len(out)])
		h.Reset()
		h.Write(out[len(out)-16:])
	}
	return LowerHex(out)
}

// interopFixedSM2K 从 caseID 派生 [1, n-1] 内的确定 k（SM2 样本签名/包装生成用）。
func interopFixedSM2K(caseID string) *big.Int {
	h := fnv.New128a()
	h.Write([]byte("k:" + caseID))
	k := new(big.Int).SetBytes(h.Sum(nil))
	return k.Mod(k, new(big.Int).Sub(sm2CurveN(), big.NewInt(1))).Add(k, big.NewInt(1))
}

func TestInteropGenerate(t *testing.T) {
	if os.Getenv("UPDATE_INTEROP") == "" {
		t.Skip("设 UPDATE_INTEROP=1 重新生成 interop 样本集")
	}
	v := loadGoldenVectors(t)
	f := interopFixture{}
	f.Meta.Format = "wop-interop-1"
	f.Meta.SpecVersion = "crypto-strategy v0.3 / sdk-spec v1.0-ratified"
	f.Meta.GeneratedBy = "wop-go-sdk@0.1.0"
	f.Meta.Note = "TEST-ONLY；verify 方向样本为冻结数据，各仓消费不得重新生成；build 方向按 input 复现"

	suites := []string{"WOP-RSA3072-SHA256", "WOP-RSA4096-SHA256", "WOP-SM2-SM3"}

	// ===== build 方向（3 套件 × L0/L2）=====
	for _, suiteID := range suites {
		for _, level := range []Level{Level0, Level2} {
			c := interopBuildCase(t, v, suiteID, level)
			f.Cases = append(f.Cases, c)
		}
	}

	// ===== verify 正向（3 套件 × L0/L2，含大小写混合头变体）=====
	for i, suiteID := range suites {
		for _, level := range []Level{Level0, Level2} {
			f.Cases = append(f.Cases, interopVerifyPositive(t, v, suiteID, level, false, fmt.Sprintf("p%02d", len(f.Cases)+1)))
			if i == 0 && level == Level0 {
				f.Cases = append(f.Cases, interopVerifyPositive(t, v, suiteID, level, true, fmt.Sprintf("p%02d", len(f.Cases)+1)))
			}
		}
	}

	// ===== verify 负向 =====
	f.Cases = append(f.Cases, interopNegatives(t, v)...)

	f.Meta.CaseCount = len(f.Cases)
	raw, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile("internal/testdata/interop-cases.json", raw, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("已生成 %d 条用例 → internal/testdata/interop-cases.json", f.Meta.CaseCount)
}

func interopBuildCase(t *testing.T, v *goldenVectors, suiteID string, level Level) interopCase {
	t.Helper()
	client := interopClient(t, v, suiteID)
	seed := "build:" + suiteID + ":" + string(level)
	draft, err := client.BuildRequest("POST", interopPath, []byte(interopPlain), level,
		WithTimestamp(1755900000000), WithNonce("interop-nonce-0000000000000001"),
		WithRandom(bytes.NewReader(mustDecodeHex(t, interopRandomHex(seed)))))
	if err != nil {
		t.Fatalf("%s: %v", suiteID, err)
	}
	isSM2 := suiteID == "WOP-SM2-SM3"
	exp := &interopBuildExpected{
		WireBodyB64: EncodeB64URL(draft.WireBody),
		Headers:     map[string]string{},
	}
	for k, val := range draft.Headers {
		exp.Headers[k] = val
	}
	if isSM2 {
		exp.ReproduceMode = "deterministic-fields"
		exp.Opaque = []string{"x-wop-sign.signatureSegment"}
		if level == Level2 {
			exp.Opaque = append(exp.Opaque, "x-wop-encrypt.dekValue")
			// L2 SM2：wire/digest 依赖 CEK/IV（随机流前段，合同内确定），保持比对
		}
	} else {
		exp.ReproduceMode = "byte-exact"
	}
	return interopCase{
		ID: seed, Kind: "build", Suite: suiteID, Level: string(level),
		Input: &interopBuildInput{
			Method: "POST", Path: interopPath, AppKey: interopAppKey,
			PlaintextB64: EncodeB64URL([]byte(interopPlain)),
			TimestampMs:  1755900000000,
			Nonce:        "interop-nonce-0000000000000001",
			RandomHex:    interopRandomHex(seed),
		},
		Expected: exp,
	}
}

// interopPlatformResponse 以平台角色构造合法响应（测试内镜像网关出站方向）。
func interopPlatformResponse(t *testing.T, v *goldenVectors, suiteID string, level Level, signPath string, plaintext []byte, kSeed string) (http.Header, []byte) {
	t.Helper()
	suite := mustSuite(t, suiteID)
	rnd := bytes.NewReader(mustDecodeHex(t, interopRandomHex("resp:"+kSeed)))
	h := http.Header{}
	h.Set(HeaderNonce, "interop-resp-nonce-0001")
	h.Set(HeaderTimestamp, "1755900000000")

	wire := []byte(nil)
	if level == Level2 {
		cek := readBytes(t, rnd, suite.cekLen())
		iv := readBytes(t, rnd, gcmIVLen)
		ct, err := sealMessage(suite, plaintext, cek, iv)
		if err != nil {
			t.Fatal(err)
		}
		wire = wrapEncryptedBody(EncodeB64URL(ct))
		var wrapped string
		if suite.IsSM2() {
			raw, werr := sm2Encrypt(interopPlatformPub(t, v, suiteID).sm2,
				[]byte(buildDekPayload(suite.MessageAlgorithm(), cek, iv)), interopFixedSM2K("wrap:"+kSeed), nil)
			if werr != nil {
				t.Fatal(werr)
			}
			wrapped = EncodeB64URL(raw)
		} else {
			var werr error
			wrapped, werr = wrapDEKPayload(suite, interopPlatformPub(t, v, suiteID),
				[]byte(buildDekPayload(suite.MessageAlgorithm(), cek, iv)), rnd)
			if werr != nil {
				t.Fatal(werr)
			}
		}
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
	} else if plaintext != nil {
		wire = plaintext
	}
	if len(wire) > 0 {
		h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
	}

	signed := map[string]string{}
	for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
		if val := h.Get(name); val != "" {
			signed[name] = val
		}
	}
	canonical := CanonicalRequest("v1/1800", "POST", signPath, "", CanonicalHeaders(signed))
	sig := interopPlatformSign(t, v, suiteID, canonical, "sign:"+kSeed)
	names := make([]string, 0, len(signed))
	for n := range signed {
		names = append(names, n)
	}
	sortStrings(names)
	h.Set(HeaderSign, buildSignHeader(suiteID, 1800, names, sig))
	return h, wire
}

func interopPlatformPub(t *testing.T, v *goldenVectors, suiteID string) *pubKey {
	t.Helper()
	switch suiteID {
	case "WOP-SM2-SM3":
		return &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	case "WOP-RSA4096-SHA256":
		p := &pubKey{}
		var err error
		if p.rsa, err = parseRSAPublicKey(v.Keys.RSA4096.PublicSpkiB64); err != nil {
			t.Fatal(err)
		}
		return p
	default:
		p := &pubKey{}
		var err error
		if p.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
			t.Fatal(err)
		}
		return p
	}
}

func interopPlatformSign(t *testing.T, v *goldenVectors, suiteID, canonical, kSeed string) string {
	t.Helper()
	suite := mustSuite(t, suiteID)
	if suite.IsSM2() {
		priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
		sig, err := sm2Sign(priv, sm2PlatformUserID, []byte(canonical), interopFixedSM2K(kSeed), nil)
		if err != nil {
			t.Fatal(err)
		}
		return EncodeB64URL(sig)
	}
	material := v.Keys.RSA3072.PrivatePkcs8B64
	if suiteID == "WOP-RSA4096-SHA256" {
		material = v.Keys.RSA4096.PrivatePkcs8B64
	}
	priv, err := parseRSAPrivateKey(material)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signMessage(suite, &privKey{rsa: priv}, sm2PlatformUserID, []byte(canonical), nil)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func interopClient(t *testing.T, v *goldenVectors, suiteID string) *Client {
	t.Helper()
	cfg := Config{AppKey: interopAppKey, SecurityReq: suiteID}
	switch suiteID {
	case "WOP-SM2-SM3":
		cfg.MerchantPrivateKey = v.Keys.SM2.PrivateDB64
		cfg.PlatformPublicKey = v.Keys.SM2.PublicPointB64
	case "WOP-RSA4096-SHA256":
		cfg.MerchantPrivateKey = v.Keys.RSA4096.PrivatePkcs8B64
		cfg.PlatformPublicKey = v.Keys.RSA4096.PublicSpkiB64
	default:
		cfg.MerchantPrivateKey = v.Keys.RSA3072.PrivatePkcs8B64
		cfg.PlatformPublicKey = v.Keys.RSA3072.PublicSpkiB64
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func interopVerifyPositive(t *testing.T, v *goldenVectors, suiteID string, level Level, mixedCase bool, id string) interopCase {
	t.Helper()
	h, wire := interopPlatformResponse(t, v, suiteID, level, interopPath, []byte(interopPlain), id)
	headers := map[string]string{}
	for name, vals := range h {
		key := name
		if mixedCase {
			key = interopMixCase(name)
		}
		headers[key] = vals[0]
	}
	return interopCase{
		ID: id, Kind: "verify-positive", Suite: suiteID, Level: string(level),
		Response: &interopResponse{
			Method: "POST", Path: interopPath, AppKey: interopAppKey,
			Headers: headers, WireBodyB64: EncodeB64URL(wire),
		},
		Expect: &interopExpect{
			OK: true, PlaintextB64: EncodeB64URL([]byte(interopPlain)),
			Description: "平台签名响应校验通过；混合大小写头名（P7）",
		},
	}
}

func interopMixCase(s string) string {
	out := []byte(s)
	for i := 0; i < len(out); i += 2 {
		if out[i] >= 'a' && out[i] <= 'z' {
			out[i] -= 'a' - 'A'
		}
	}
	return string(out)
}

var _ = rsa.PublicKey{}
var _ = ecdsa.PublicKey{}

// interopNegatives 构造异常场景负样本（对齐故障注入手册 P 系列与 D2/I1/I5/I7 合同）。
// 纪律：凡篡改发生在签名前的，digest 与签名按篡改后载体重算（否则死在摘要层，到不了目标层）。
func interopNegatives(t *testing.T, v *goldenVectors) []interopCase {
	t.Helper()
	rsaID, sm2ID := "WOP-RSA3072-SHA256", "WOP-SM2-SM3"
	resp := func(id, suiteID string, level Level, mutate func(*http.Header, []byte) ([]byte, string)) interopCase {
		h, wire := interopPlatformResponse(t, v, suiteID, level, interopPath, []byte(interopPlain), id)
		newWire, expectClass := mutate(&h, wire)
		headers := map[string]string{}
		for name, vals := range h {
			headers[name] = vals[0]
		}
		return interopCase{
			ID: id, Kind: "verify-negative", Suite: suiteID, Level: string(level),
			Response: &interopResponse{
				Method: "POST", Path: interopPath, AppKey: interopAppKey,
				Headers: headers, WireBodyB64: EncodeB64URL(newWire),
			},
			Expect: &interopExpect{OK: false, ErrorClass: expectClass},
		}
	}
	// resign：按当前头重算 digest 与签名（篡改后仍保持全链合法，直达目标层）
	resign := func(t *testing.T, v *goldenVectors, suiteID string, h *http.Header, wire []byte, kSeed string) {
		suite := mustSuite(t, suiteID)
		h.Del(HeaderContentDigest)
		if len(wire) > 0 {
			h.Set(HeaderContentDigest, DigestHeaderValue(suite, wire))
		}
		signed := map[string]string{}
		for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
			if val := h.Get(name); val != "" {
				signed[name] = val
			}
		}
		canonical := CanonicalRequest("v1/1800", "POST", interopPath, "", CanonicalHeaders(signed))
		sig := interopPlatformSign(t, v, suiteID, canonical, kSeed)
		names := make([]string, 0, len(signed))
		for n := range signed {
			names = append(names, n)
		}
		sortStrings(names)
		h.Set(HeaderSign, buildSignHeader(suiteID, 1800, names, sig))
	}

	// resignKeepDigest 按当前 digest 头值重签（不重算 digest）——用于"签名自洽但
	// digest 标签跨族"等结构注入场景。
	resignKeepDigest := func(t *testing.T, v *goldenVectors, suiteID string, h *http.Header, wire []byte, kSeed string) {
		signed := map[string]string{}
		for _, name := range []string{HeaderNonce, HeaderTimestamp, HeaderContentDigest, HeaderEncrypt} {
			if val := h.Get(name); val != "" {
				signed[name] = val
			}
		}
		canonical := CanonicalRequest("v1/1800", "POST", interopPath, "", CanonicalHeaders(signed))
		sig := interopPlatformSign(t, v, suiteID, canonical, kSeed)
		names := make([]string, 0, len(signed))
		for n := range signed {
			names = append(names, n)
		}
		sortStrings(names)
		h.Set(HeaderSign, buildSignHeader(suiteID, 1800, names, sig))
	}

	var cases []interopCase

	// n01 P1：信封密文单字符损伤（保 b64url 合法），digest+签名重算 → 解密类模糊
	cases = append(cases, resp("n01-encrypted-char-damage", rsaID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		w = append([]byte{}, w...)
		i := len(w) / 2
		if w[i] == 'A' {
			w[i] = 'B'
		} else {
			w[i] = 'A'
		}
		resign(t, v, rsaID, h, w, "n01")
		return w, "decrypt-failed"
	}))

	// n02 篡改线上体（签名后追加）→ digest 不匹配（完整性类明确，先于解密）
	cases = append(cases, resp("n02-wire-tampered-after-signing", rsaID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		return append(append([]byte{}, w...), 'x'), "digest-mismatch"
	}))

	// n03 I5：digest 标签跨族（RSA 套件 + sm3 标签）。构造非合规平台：digest 用 sm3
	// 标签但签名覆盖该值（签名自洽），族耦合校验先于值比对生效 → 协议类
	cases = append(cases, resp("n03-digest-tag-cross-family", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		h.Set(HeaderContentDigest, DigestHeaderValue(mustSuite(t, sm2ID), w))
		resignKeepDigest(t, v, rsaID, h, w, "n03")
		return w, "protocol"
	}))

	// n04 I3：DEK alg 跨族（SM2 套件 + AES-256-GCM 声明），密文为垃圾 → 一致性类（先于解密）
	cases = append(cases, resp("n04-dek-alg-cross-family", sm2ID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		rnd := bytes.NewReader(mustDecodeHex(t, interopRandomHex("n04")))
		w = wrapEncryptedBody(EncodeB64URL([]byte("garbage-ciphertext-16b")))
		n04k := interopFixedSM2K("wrap:n04")
		n04raw, err := sm2Encrypt(mustSM2Pub(t, v.Keys.SM2.PublicPointB64),
			[]byte(buildDekPayload("AES-256-GCM", readBytes(t, rnd, 32), readBytes(t, rnd, gcmIVLen))), n04k, nil)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := EncodeB64URL(n04raw)
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
		resign(t, v, sm2ID, h, w, "n04")
		return w, "alg-mismatch"
	}))

	// n05 D9：SM2 DEK 密文 C1C2C3 旧序拼装 → 解密类模糊（顺序钉死）
	cases = append(cases, resp("n05-dek-c1c2c3-order", sm2ID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		suite := mustSuite(t, sm2ID)
		rnd := bytes.NewReader(mustDecodeHex(t, interopRandomHex("n05")))
		cek := readBytes(t, rnd, suite.cekLen())
		iv := readBytes(t, rnd, gcmIVLen)
		ct, err := sealMessage(suite, []byte(interopPlain), cek, iv)
		if err != nil {
			t.Fatal(err)
		}
		w = wrapEncryptedBody(EncodeB64URL(ct))
		ct1c3c2, err := sm2Encrypt(mustSM2Pub(t, v.Keys.SM2.PublicPointB64),
			[]byte(buildDekPayload(suite.MessageAlgorithm(), cek, iv)), interopFixedSM2K("wrap:n05"), nil)
		if err != nil {
			t.Fatal(err)
		}
		// C1(65) C3(32) C2 → C1 C2 C3 重排
		c1 := ct1c3c2[:65]
		c3 := ct1c3c2[65:97]
		c2 := ct1c3c2[97:]
		wrapped := EncodeB64URL(append(append(append([]byte{}, c1...), c2...), c3...))
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
		resign(t, v, sm2ID, h, w, "n05")
		return w, "decrypt-failed"
	}))

	// n06 P6：签名段携带 '='（模拟中间层 urlencode 污染）→ 协议类（公开结构知识，严格 b64url 拒收）
	cases = append(cases, resp("n06-signature-b64-padding", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		sig := h.Get(HeaderSign)
		h.Set(HeaderSign, sig+"=")
		return w, "protocol"
	}))

	// n07 SM2 签名 63B（截尾）→ 协议类（定长前置）
	cases = append(cases, resp("n07-signature-63b", sm2ID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		parsed, _ := ParseSignHeader(h.Get(HeaderSign))
		sig := parsed.signature
		h.Set(HeaderSign, buildSignHeader(sm2ID, 1800, parsed.signedHeaders, sig[:len(sig)-2]))
		return w, "protocol"
	}))

	// n08 SM2 签名 65B（前补零字节）→ 协议类
	cases = append(cases, resp("n08-signature-65b", sm2ID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		parsed, _ := ParseSignHeader(h.Get(HeaderSign))
		h.Set(HeaderSign, buildSignHeader(sm2ID, 1800, parsed.signedHeaders, "AA"+parsed.signature))
		return w, "protocol"
	}))

	// n09 D2：有 body 缺 digest 头 → 完整性类明确
	cases = append(cases, resp("n09-digest-missing", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		h.Del(HeaderContentDigest)
		return w, "digest-mismatch"
	}))

	// n10 I1：digest 头存在且正确，但 signedHeaders 未列 → 协议类（body 与签名绑定桥梁）
	cases = append(cases, resp("n10-digest-not-signed", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		parsed, _ := ParseSignHeader(h.Get(HeaderSign))
		var without []string
		for _, name := range parsed.signedHeaders {
			if name != HeaderContentDigest {
				without = append(without, name)
			}
		}
		h.Set(HeaderSign, buildSignHeader(parsed.securityReq, parsed.expiredSeconds, without, parsed.signature))
		return w, "protocol"
	}))

	// n11 响应声明套件与商户配置不符 → 协议类
	cases = append(cases, resp("n11-suite-mismatch", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		sig := h.Get(HeaderSign)
		h.Set(HeaderSign, "WOP-RSA4096-SHA256"+sig[len(rsaID):])
		return w, "protocol"
	}))

	// n12 P2：信封缺 encrypted 字段（结构层）→ 协议类（与 n01 构成 I7 分界对照）
	cases = append(cases, resp("n12-envelope-missing-field", rsaID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		w = []byte(`{"data":"no-encrypted-field"}`)
		resign(t, v, rsaID, h, w, "n12")
		return w, "protocol"
	}))

	// n13 P3：DEK 载荷 key 段长度错（AES 31B），alg 正确、外层全链合法 → 解密类模糊
	cases = append(cases, resp("n13-dek-key-length", rsaID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		suite := mustSuite(t, rsaID)
		rnd := bytes.NewReader(mustDecodeHex(t, interopRandomHex("n13")))
		cek := readBytes(t, rnd, suite.cekLen())
		iv := readBytes(t, rnd, gcmIVLen)
		ct, err := sealMessage(suite, []byte(interopPlain), cek, iv)
		if err != nil {
			t.Fatal(err)
		}
		w = wrapEncryptedBody(EncodeB64URL(ct))
		wrapped, err := wrapDEKPayload(suite, interopPlatformPub(t, v, rsaID),
			[]byte(buildDekPayload(suite.MessageAlgorithm(), cek[:31], iv)), rnd)
		if err != nil {
			t.Fatal(err)
		}
		h.Set(HeaderEncrypt, buildEncryptHeader(wrapped))
		resign(t, v, rsaID, h, w, "n13")
		return w, "decrypt-failed"
	}))

	// n14 signedHeaders 声明了缺失的头 → 协议类
	cases = append(cases, resp("n14-missing-signed-header", rsaID, Level0, func(h *http.Header, w []byte) ([]byte, string) {
		parsed, _ := ParseSignHeader(h.Get(HeaderSign))
		h.Set(HeaderSign, buildSignHeader(parsed.securityReq, parsed.expiredSeconds,
			append(append([]string{}, parsed.signedHeaders...), "x-wop-extra"), parsed.signature))
		return w, "protocol"
	}))

	// n15 D2：无 body 却携带 digest 头 → 协议类
	cases = append(cases, interopCase{
		ID: "n15-digest-without-body", Kind: "verify-negative", Suite: rsaID, Level: "L0",
		Response: func() *interopResponse {
			h, wire := interopPlatformResponse(t, v, rsaID, Level0, interopPath, nil, "n15")
			h.Set(HeaderContentDigest, DigestHeaderValue(mustSuite(t, rsaID), nil))
			headers := map[string]string{}
			for name, vals := range h {
				headers[name] = vals[0]
			}
			return &interopResponse{
				Method: "POST", Path: interopPath, AppKey: interopAppKey,
				Headers: headers, WireBodyB64: EncodeB64URL(wire),
			}
		}(),
		Expect: &interopExpect{OK: false, ErrorClass: "protocol"},
	})

	// n16 前置：x-wop-encrypt 值为裸 "L2"（缺 ";dek=" 段）→ 协议类（公开头结构知识，组织裁决）
	cases = append(cases, resp("n17-encrypt-missing-dek", rsaID, Level2, func(h *http.Header, w []byte) ([]byte, string) {
		h.Set(HeaderEncrypt, "L2")
		resignKeepDigest(t, v, rsaID, h, w, "n17")
		return w, "protocol"
	}))

	// P5：跨端点签名重放（签名覆盖 /gateway/pay，用 /gateway/refund 校验）→ 验签类模糊
	cases = append(cases, interopCase{
		ID: "n16-replay-cross-path", Kind: "verify-negative", Suite: rsaID, Level: "L0",
		Response: func() *interopResponse {
			h, wire := interopPlatformResponse(t, v, rsaID, Level0, "/gateway/pay", []byte(interopPlain), "n16")
			headers := map[string]string{}
			for name, vals := range h {
				headers[name] = vals[0]
			}
			return &interopResponse{
				Method: "POST", Path: "/gateway/pay", AppKey: interopAppKey,
				Headers: headers, WireBodyB64: EncodeB64URL(wire),
			}
		}(),
		VerifyPath: "/gateway/refund",
		Expect:     &interopExpect{OK: false, ErrorClass: "verify-failed"},
	})

	return cases
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("hex 长度非法")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexNibble(t, s[i*2])
		lo := hexNibble(t, s[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexNibble(t *testing.T, c byte) byte {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	t.Fatalf("非 hex 字符 %q", c)
	return 0
}
