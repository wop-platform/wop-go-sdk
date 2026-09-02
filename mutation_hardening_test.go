package wop

// 变异强化测试：针对第一轮变异测试存活的"真盲区"变异体。
// 每组测试上方标注所杀变异（算子 文件:行），其余存活者见交付报告的
// 等价变异论证（结构等价/诊断文案/不可达防御）。

import (
	"bytes"
	"encoding/base64"
	"io"
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

// spec:D4 OKN 字面量锚 transport.go:33 —— D4 条文：响应体上限 11MB（11<<20 = 11534336 字节），
// 读取过程中生效（超限即断流）。既有边界测试（TestDefaultTransport_ResponseLimitBoundary 及
// transport_test.go 超限分支）均以 maxResponseBytes 常量构造请求与断言，与实现自指：
// 变异审计档案（wop-specs docs/mutation-survivors-wop-go-sdk.md review 组）记录的两个 OKN
// 幸存体（transport.go:33:26 11→12、transport.go:33:32 20→21，均为升上限方向）因此不可见。
// 本测试改用字面量钉死两端，裁决为补锚测试而非白名单：
//   - 恰 11534336 字节必须通过且完整读到 —— 击杀「降上限」方向 OKN；
//   - 11534337 字节必须拒绝（CodeParse）—— 击杀「升上限」方向 OKN（含档案两个幸存体）。
func TestDefaultTransport_ResponseLimitLiteralAnchor_SpecD4(t *testing.T) {
	const capLiteral = 11534336 // = 11 * 1024 * 1024 = 11 << 20（spec D4 字面量锚，勿改用常量）

	// 下界锚：恰 11MiB（11534336 字节）通过，响应体完整返回
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{0x61}, capLiteral))
	}))
	defer srvOK.Close()
	resp, err := DefaultTransport{HTTPClient: srvOK.Client(), BaseURL: srvOK.URL}.
		Send(RequestDraft{Method: "GET", Path: "/x"})
	if err != nil {
		t.Fatalf("恰 11534336 字节（11MiB）响应应通过: %v", err)
	}
	if len(resp.Body) != capLiteral {
		t.Fatalf("body 长度 = %d, want 11534336", len(resp.Body))
	}

	// 上界锚：11534337 字节（11MiB+1）拒绝，类别 CodeParse
	srvOver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{0x61}, capLiteral+1))
	}))
	defer srvOver.Close()
	trOver := DefaultTransport{HTTPClient: srvOver.Client(), BaseURL: srvOver.URL}
	if _, err := trOver.Send(RequestDraft{Method: "GET", Path: "/x"}); err == nil {
		t.Fatal("11534337 字节（11MiB+1）响应应拒绝")
	} else if err.(*Error).Code != CodeParse {
		t.Fatalf("超限错误类 = %s, want parse", err.(*Error).Code)
	}
}

// spec:D4 流式断流锚 transport.go:64 —— D4 条文「读取过程中生效（超限即断流）」：
// 限额必须在读取流上生效，超限响应的底层读取量钉死在 maxResponseBytes+1 字节，
// 禁止退化为无界整体缓冲后才检查长度。字面量锚测试（上）只验证边界判定结果，
// 无法区分「LimitReader 截断」与「ReadAll 全量缓冲后拒绝」（Sourcery review 指出的缺口），
// 本测试以计数 body 钉死读取量语义：
//   - 底层流可提供 12582912 字节（12MiB，远超上限）；
//   - Send 拒绝（CodeParse）后底层累计读取必须恰为 11534337 字节（11MiB+1），
//     即超限判定所需的最小读取量——任何多余读取即「整体缓冲」回归。
func TestDefaultTransport_ResponseLimitStopsReadingAtCap_SpecD4(t *testing.T) {
	const capLiteral = 11534336 // = 11 << 20（spec D4 字面量锚，勿改用常量）

	body := &countingReadCloser{remain: capLiteral + (1 << 20)} // 12MiB 可读流
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			Body:          body,
			ContentLength: int64(capLiteral + (1 << 20)),
		}, nil
	})
	_, err := DefaultTransport{HTTPClient: &http.Client{Transport: rt}, BaseURL: "https://gw.example.test"}.
		Send(RequestDraft{Method: "GET", Path: "/x"})
	if err == nil || err.(*Error).Code != CodeParse {
		t.Fatalf("超限响应应拒绝且错误类为 parse, got %v", err)
	}
	if body.read != capLiteral+1 {
		t.Fatalf("底层累计读取 = %d 字节, want %d（LimitReader 须在 11MiB+1 处断流，不得耗尽完整流）",
			body.read, capLiteral+1)
	}
}

// countingReadCloser 记录底层累计读取量的响应体（流式断流断言用）。
type countingReadCloser struct {
	remain int
	read   int
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	if c.remain == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > c.remain {
		n = c.remain
	}
	c.remain -= n
	c.read += n
	return n, nil
}

func (c *countingReadCloser) Close() error { return nil }

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
			return TransportResponse{}, newError(CodeConfiguration, "注入的发送失败")
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
	if err == nil || err.(*Error).Code != CodeConfiguration {
		t.Errorf("CEK 读取耗尽应报 configuration，实际 %v", err)
	}

	// 恰 48 字节：nonce(16)+CEK(32) 成功后 IV 读取失败
	_, err = c.BuildRequest("POST", "/x", []byte("data"), Level2,
		WithRandom(bytes.NewReader(make([]byte, 48))))
	if err == nil || err.(*Error).Code != CodeConfiguration {
		t.Errorf("IV 读取耗尽应报 configuration，实际 %v", err)
	}
}

// COI keys.go:81 + LOR/OBB/OKN keys.go:102 —— SM2 私钥标量范围 [1, n-1]
// 前置校验（不依赖下游库兜底）：d=0、d=n 必须被前置拒绝（*Error/CONFIG）。
func TestParseSM2PrivateKey_ScalarRange(t *testing.T) {
	n := sm2CurveN()
	dZero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := parseSM2PrivateKey(dZero); err == nil {
		t.Error("d=0 应拒绝")
	} else if we, ok := err.(*Error); !ok || we.Code != CodeConfiguration {
		t.Errorf("d=0 应为前置 configuration 错误（非下游库兜底），实际 %v", err)
	}
	dN := base64.StdEncoding.EncodeToString(pad32(n))
	if _, err := parseSM2PrivateKey(dN); err == nil {
		t.Error("d=n 应拒绝")
	} else if we, ok := err.(*Error); !ok || we.Code != CodeConfiguration {
		t.Errorf("d=n 应为前置 configuration 错误（非下游库兜底），实际 %v", err)
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
	} else if err.(*Error).Code != CodeConfiguration {
		t.Errorf("错误类 = %s, want configuration", err.(*Error).Code)
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
