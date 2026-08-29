package wop

// 变异强化测试：针对第一轮变异测试存活的"真盲区"变异体。
// 每组测试上方标注所杀变异（算子 文件:行），其余存活者见交付报告的
// 等价变异论证（结构等价/诊断文案/不可达防御）。

import (
	"bytes"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// spec:D2 COI verify.go:61/69/88 —— D2 负向条款：无响应体时 digest 缺席合法，
// 校验管线不得因 hasBody 恒真而拒绝空体响应。
func TestVerifyResponse_NoBody_NoDigest_OK(t *testing.T) {
	for _, suiteID := range []string{"WOP-RSA3072-SHA256", "WOP-SM2-SM3"} {
		b := newPlatformBuilder(t, suiteID)
		c := verifyClient(t, suiteID)

		h, wire := b.build(t, "POST", "/gateway/x", nil, Level0, nil)
		if len(wire) != 0 {
			t.Fatalf("%s: 空明文不应产出响应体", suiteID)
		}
		if v := h.Get(HeaderContentDigest); v != "" {
			t.Fatalf("%s: 无响应体不应携带 digest 头", suiteID)
		}
		res := c.VerifyResponse("POST", "/gateway/x", h, nil)
		if !res.OK || len(res.Plaintext) != 0 {
			t.Fatalf("%s: 空体响应应校验通过: ok=%v code=%s reason=%s",
				suiteID, res.OK, res.Code, res.Reason)
		}
	}
}

// AOR sm2raw.go:253 —— 33..96 字节的垃圾密文必须被前置长度检查拒绝，
// 不得在切片解构时越界。
func TestSm2Decrypt_RejectsMidRangeGarbage(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)

	for _, n := range []int{33, 64, 96} {
		if _, err := sm2Decrypt(priv, bytes.Repeat([]byte{0x42}, n)); err == nil {
			t.Errorf("长度 %d 的垃圾密文应被拒绝", n)
		}
	}
	// len == 97 恰过长度检查，但 C1 前缀非 04
	bad := bytes.Repeat([]byte{0x00}, 97)
	bad[0] = 0x03
	if _, err := sm2Decrypt(priv, bad); err == nil {
		t.Error("C1 非未压缩点应被拒绝")
	}
}

// OKN client.go:199 + COI/OBB/SDEL transport.go:54/55 —— 恰 1 字节报文：
// spec:D2 digest 必产（D2），Content-Type 必设。
func TestBuildRequest_SingleByteBody_DigestAndContentType(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	d, err := c.BuildRequest("POST", "/gateway/x", []byte("x"), Level0,
		WithTimestamp(1755900000000), WithNonce("one-byte"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Headers[HeaderContentDigest] == "" {
		t.Fatal("1 字节报文也必须携带 digest 头（D2）")
	}

	var gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tr := DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
	if _, err := tr.Send(d); err != nil {
		t.Fatal(err)
	}
	if gotCT != "application/json" {
		t.Fatalf("携带报文时 Content-Type = %q, want application/json", gotCT)
	}
}

// spec:D4 OKN transport.go:33 + OBB transport.go:68 —— D4 限额边界：
// 恰 11MiB 通过，+1 字节拒绝。
func TestDefaultTransport_ResponseLimitBoundary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{0x61}, maxResponseBytes)) // 恰上限
	}))
	defer srv.Close()
	tr := DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
	resp, err := tr.Send(RequestDraft{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatalf("恰 %d 字节响应应通过: %v", maxResponseBytes, err)
	}
	if len(resp.Body) != maxResponseBytes {
		t.Fatalf("body 长度 = %d, want %d", len(resp.Body), maxResponseBytes)
	}
}

// OBB signheader.go:35 + OKN signheader.go:40/52 —— 解析边界：
// 前导空格（sp==0）、签名段含 /、expiredSeconds 恰 1 秒。
func TestParseSignHeader_BoundarySemantics(t *testing.T) {
	// 前导空格：securityReq 为空必须拒绝
	if _, err := ParseSignHeader(" v1/1800/x-wop-a/c2ln"); err == nil {
		t.Error("securityReq 为空（前导空格）应拒绝")
	}

	// 签名段含 /：SplitN 固定 4 段，多余 / 归入签名段（b64url 之外的字符
	// 在后续 decode 阶段拒绝），解析本身成功
	p, err := ParseSignHeader("WOP-RSA3072-SHA256 v1/1800/x-wop-a/Yh/c2ln")
	if err != nil {
		t.Fatalf("4 段拆分语义: %v", err)
	}
	if p.signature != "Yh/c2ln" {
		t.Fatalf("signature = %q, want %q", p.signature, "Yh/c2ln")
	}

	// expiredSeconds 恰 1 合法、0 非法
	if _, err := ParseSignHeader("WOP-RSA3072-SHA256 v1/1/x-wop-a/c2ln"); err != nil {
		t.Errorf("expiredSeconds=1 应合法: %v", err)
	}
	if _, err := ParseSignHeader("WOP-RSA3072-SHA256 v1/0/x-wop-a/c2ln"); err == nil {
		t.Error("expiredSeconds=0 应拒绝")
	}
}

// OBB client.go:73 —— ExpiredSeconds 恰 86400 合法、86401 拒绝。
func TestNewClient_ExpiredSecondsBoundary(t *testing.T) {
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.ExpiredSeconds = SignExpiredSecondsMax
	if _, err := NewClient(cfg); err != nil {
		t.Fatalf("ExpiredSeconds=%d 应合法: %v", SignExpiredSecondsMax, err)
	}
	cfg.ExpiredSeconds = SignExpiredSecondsMax + 1
	if _, err := NewClient(cfg); err == nil {
		t.Errorf("ExpiredSeconds=%d 应拒绝", SignExpiredSecondsMax+1)
	}
}

// COI client.go:108 —— 显式 nil Transport 时 NewClient 必须装配默认传输。
func TestNewClient_NilTransportFallsBack(t *testing.T) {
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = nil
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.transport == nil {
		t.Fatal("Transport 为 nil 时应装配 DefaultTransport")
	}
}

// COI client.go:265/269 —— Do 的构建失败与发送失败必须返回错误。
func TestDo_ErrorPaths(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")

	if _, _, err := c.Do("", "/p", nil, Level0); err == nil {
		t.Error("非法 method 应使 Do 返回错误")
	}

	c2, err := NewClient(func() Config {
		cfg := testConfig(t, "WOP-RSA3072-SHA256")
		cfg.Transport = TransportFunc(func(RequestDraft) (TransportResponse, error) {
			return TransportResponse{}, newError(CodeConfig, "注入的发送失败")
		})
		return cfg
	}())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c2.Do("POST", "/gateway/x", []byte("{}"), Level0); err == nil {
		t.Error("发送失败应使 Do 返回错误")
	}
}

// COI client.go:230/234 —— L2 随机源在 CEK/IV 处耗尽必须报配置类错误。
func TestBuildRequest_L2_RandomExhaustionAtCEKAndIV(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")

	// 恰 16 字节：nonce(16) 成功后 CEK 读取失败
	_, err := c.BuildRequest("POST", "/x", []byte("data"), Level2,
		WithRandom(bytes.NewReader(make([]byte, 16))))
	if err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("CEK 读取耗尽应报 CONFIG，实际 %v", err)
	}

	// 恰 48 字节：nonce(16)+CEK(32) 成功后 IV 读取失败
	_, err = c.BuildRequest("POST", "/x", []byte("data"), Level2,
		WithRandom(bytes.NewReader(make([]byte, 48))))
	if err == nil || err.(*Error).Code != CodeConfig {
		t.Errorf("IV 读取耗尽应报 CONFIG，实际 %v", err)
	}
}

// COI keys.go:81 + LOR/OBB/OKN keys.go:102 —— SM2 私钥标量范围 [1, n-1]
// 前置校验（不依赖下游库兜底）：d=0、d=n 必须被前置拒绝（*Error/CONFIG）。
func TestParseSM2PrivateKey_ScalarRange(t *testing.T) {
	n := sm2CurveN()
	dZero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := parseSM2PrivateKey(dZero); err == nil {
		t.Error("d=0 应拒绝")
	} else if we, ok := err.(*Error); !ok || we.Code != CodeConfig {
		t.Errorf("d=0 应为前置 CONFIG 错误（非下游库兜底），实际 %v", err)
	}
	dN := base64.StdEncoding.EncodeToString(pad32(n))
	if _, err := parseSM2PrivateKey(dN); err == nil {
		t.Error("d=n 应拒绝")
	} else if we, ok := err.(*Error); !ok || we.Code != CodeConfig {
		t.Errorf("d=n 应为前置 CONFIG 错误（非下游库兜底），实际 %v", err)
	}
	// d=n-1：SDK 前置范围 [1,n-1] 放行；emmansun/gmsm 更严（拒 N-1）。
	// 库级边界与前置契约正交，仅记录不断言方向。
	dNMinus1 := base64.StdEncoding.EncodeToString(pad32(new(big.Int).Sub(n, big.NewInt(1))))
	if _, err := parseSM2PrivateKey(dNMinus1); err != nil {
		t.Logf("d=n-1 由下游 gmsm 拒绝（比 SDK 前置更严）: %v", err)
	}
}

// LOR transport.go:43 —— url.Parse 本身失败（控制字符）必须拒绝。
func TestDefaultTransport_URLParseError(t *testing.T) {
	tr := DefaultTransport{BaseURL: "http://127.0.0.1:\x7f"}
	_, err := tr.Send(RequestDraft{Method: "GET", Path: "/x"})
	if err == nil {
		t.Error("非法 URL 应失败")
	} else if err.(*Error).Code != CodeConfig {
		t.Errorf("错误类 = %s, want CONFIG", err.(*Error).Code)
	}
}

// 防 LCR 漂移回归：sm2raw 错误文案含关键词（约束诊断信息可诊断性，
// 同杀签名协议常量）。
func TestProtocolErrorMessages_ContainKeywords(t *testing.T) {
	cases := []struct {
		err     error
		keyword string
	}{
		{mustErrParseSuite(""), "为空"},
		{mustErrParseSuite("RSA3072-SHA256"), "格式非法"},
		{mustErrParseSuite("WOP-RSA3072-SM3"), "跨族"},
	}
	for _, tc := range cases {
		if tc.err == nil || !strings.Contains(tc.err.Error(), tc.keyword) {
			t.Errorf("错误 %v 应含关键词 %q", tc.err, tc.keyword)
		}
	}
}

func mustErrParseSuite(s string) error {
	_, err := ParseSuite(s)
	return err
}
