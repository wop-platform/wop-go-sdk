package wop

// 变异强化第四批：链式同码错误掩盖点。变异跳过前置检查后，下游会以
// 同类错误兜底（或反向：本应失败的场景被兜底成功），仅凭 err≠nil/码
// 相同无法区分来源 —— 本批以错误来源细节（文案关键词、错误类型、副作用
// 有无）钉死每个前置检查的独立存在价值。

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// COI client.go:230 —— CEK 耗尽与 IV 耗尽必须可区分（文案锚点）。
func TestBuildRequest_L2_CEKExhaustionDistinguished(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	_, err := c.BuildRequest("POST", "/x", []byte("data"), Level2,
		WithRandom(bytes.NewReader(make([]byte, 16))))
	if err == nil || !strings.Contains(err.Error(), "CEK") {
		t.Errorf("CEK 耗尽错误须含 CEK 关键词，实际 %v", err)
	}
}

// COI client.go:265/269 —— Do 的错误来源可区分：构建期（文案）/发送期（注入码）。
func TestDo_ErrorSourcesDistinguished(t *testing.T) {
	c := verifyClient(t, "WOP-RSA3072-SHA256")
	_, _, err := c.Do("", "/p", nil, Level0)
	if err == nil || !strings.Contains(err.Error(), "method") {
		t.Errorf("构建期错误须含 method 关键词，实际 %v", err)
	}

	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = TransportFunc(func(RequestDraft) (TransportResponse, error) {
		return TransportResponse{}, newError(CodeConfig, "注入的发送失败")
	})
	c2, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c2.Do("POST", "/gateway/x", []byte("{}"), Level0)
	we, ok := err.(*Error)
	if !ok || we.Code != CodeConfig || we.Message != "注入的发送失败" {
		t.Errorf("发送期错误须原样透传，实际 %v", err)
	}
}

// COI/LOR keys.go:81 —— SM2 公钥 65B 前置检查独立于下游库校验
// （64B 且 04 开头的输入：前置拒为 *Error，跳过后 NewPublicKey 拒为库错误）。
func TestParseSM2PublicKey_LengthPreflight(t *testing.T) {
	raw := make([]byte, 64)
	raw[0] = 0x04
	if _, err := parseSM2PublicKey(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("64B 公钥应拒绝")
	} else if we, ok := err.(*Error); !ok || we.Code != CodeConfig {
		t.Errorf("64B 公钥应为前置 CONFIG 错误，实际 %T %v", err, err)
	}
}

// AOR/COI sm2raw.go:253 —— 长度下限 97（65+32）是切片解构前置条件：
// 40B、04 开头的密文必须被长度检查拒绝，不得进入切片解构（越界）。
func TestSm2Decrypt_LengthPreflightBeforeSlicing(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)

	garbage := make([]byte, 40)
	garbage[0] = 0x04
	if _, err := sm2Decrypt(priv, garbage); err == nil {
		t.Error("40B 密文应被长度前置检查拒绝")
	}
}

// COI/OBB transport.go:54 —— 无报文请求不得携带 Content-Type。
func TestDefaultTransport_NoBodyNoContentType(t *testing.T) {
	var gotCT string
	var hasCT bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		_, hasCT = r.Header["Content-Type"]
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tr := DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
	if _, err := tr.Send(RequestDraft{Method: "GET", Path: "/x"}); err != nil {
		t.Fatal(err)
	}
	if hasCT && gotCT != "" {
		t.Errorf("无报文请求不应设置 Content-Type，实际 %q", gotCT)
	}
}
