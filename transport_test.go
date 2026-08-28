package wop

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Transport：DefaultTransport + RoundTripper 桥接 + Client.Do 全链路（httptest）。
func TestDefaultTransport_SendsDraft(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody []byte
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotHeaders = r.Method, r.URL.Path, r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Test", "1")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("resp"))
	}))
	defer srv.Close()

	tr := DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
	draft := RequestDraft{
		Method:   "POST",
		Path:     "/gateway/x",
		Headers:  map[string]string{HeaderAppKey: "ak", HeaderSign: "sig"},
		WireBody: []byte("body"),
	}
	resp, err := tr.Send(draft)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != "POST" || gotPath != "/gateway/x" {
		t.Errorf("method/path = %s %s", gotMethod, gotPath)
	}
	if gotHeaders.Get(HeaderAppKey) != "ak" || gotHeaders.Get(HeaderSign) != "sig" {
		t.Errorf("headers 未透传: %v", gotHeaders)
	}
	if !bytes.Equal(gotBody, []byte("body")) {
		t.Errorf("body = %q", gotBody)
	}
	if resp.StatusCode != 200 || string(resp.Body) != "resp" || resp.Headers.Get("X-Test") != "1" {
		t.Errorf("resp: %d %q", resp.StatusCode, resp.Body)
	}
}

func TestClient_Do_EndToEnd_L0_L2(t *testing.T) {
	for _, suiteID := range []string{"WOP-RSA3072-SHA256", "WOP-SM2-SM3"} {
		b := newPlatformBuilder(t, suiteID)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 网关侧：读取商户请求并回一个平台签名的 L2 响应
			h, wire := b.build(t, "POST", r.URL.Path, []byte(`{"code":"SUCCESS","data":{"k":1}}`), Level2, nil)
			for _, name := range []string{HeaderSign, HeaderTimestamp, HeaderNonce, HeaderContentDigest, HeaderEncrypt} {
				if v := h.Get(name); v != "" {
					w.Header().Set(name, v)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(wire)
		}))
		defer srv.Close()

		cfg := testConfig(t, suiteID)
		cfg.GatewayBaseURL = srv.URL
		cfg.Transport = DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
		client, err := NewClient(cfg)
		if err != nil {
			t.Fatal(err)
		}

		res, resp, err := client.Do("POST", "/gateway/echo", []byte(`{"q":1}`), Level2)
		if err != nil {
			t.Fatalf("%s Do: %v", suiteID, err)
		}
		if !res.OK || string(res.Plaintext) != `{"code":"SUCCESS","data":{"k":1}}` {
			t.Fatalf("%s: ok=%v code=%s reason=%s", suiteID, res.OK, res.Code, res.Reason)
		}
		if resp.StatusCode != 200 {
			t.Errorf("status = %d", resp.StatusCode)
		}

		// L0 路径
		res, _, err = client.Do("POST", "/gateway/echo", []byte(`{"q":2}`), Level0)
		if err != nil || !res.OK {
			t.Errorf("%s L0 Do: err=%v ok=%v", suiteID, err, res.OK)
		}
	}
}

// 响应验签失败 → Do 返回 wop.Error，Code 可编程处理。
func TestClient_Do_VerifyFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"code":"SUCCESS"}`)) // 无签名头
	}))
	defer srv.Close()

	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = DefaultTransport{HTTPClient: srv.Client(), BaseURL: srv.URL}
	client, _ := NewClient(cfg)

	res, _, err := client.Do("POST", "/p", []byte("x"), Level0)
	if err == nil {
		t.Fatal("应返回错误")
	}
	we, ok := err.(*Error)
	if !ok || we.Code != res.Code || res.OK {
		t.Errorf("err=%v res=%+v", err, res)
	}
}

func TestRoundTripperTransport_Bridge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	called := false
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return http.DefaultTransport.RoundTrip(req)
	})
	tr := RoundTripperTransport(rt, srv.URL)
	resp, err := tr.Send(RequestDraft{Method: "GET", Path: "/x"})
	if err != nil || string(resp.Body) != "ok" || !called {
		t.Fatalf("bridge: err=%v body=%q called=%v", err, resp.Body, called)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTransportFunc_Mock(t *testing.T) {
	tr := TransportFunc(func(d RequestDraft) (TransportResponse, error) {
		return TransportResponse{StatusCode: 201, Headers: http.Header{}, Body: []byte("mock")}, nil
	})
	resp, err := tr.Send(RequestDraft{})
	if err != nil || resp.StatusCode != 201 || string(resp.Body) != "mock" {
		t.Fatalf("mock: %+v %v", resp, err)
	}
}

func TestDefaultTransport_Errors(t *testing.T) {
	// 非法 URL（相对路径且无 BaseURL）
	if _, err := (DefaultTransport{}).Send(RequestDraft{Method: "GET", Path: "/only/path"}); err == nil {
		t.Error("相对路径无 BaseURL 应失败")
	} else if err.(*Error).Code != CodeConfig {
		t.Errorf("错误类 = %s", err.(*Error).Code)
	}

	// 网络错误
	if _, err := (DefaultTransport{BaseURL: "http://127.0.0.1:1"}).Send(
		RequestDraft{Method: "GET", Path: "/x"}); err == nil {
		t.Error("连接拒绝应失败")
	}

	// 响应体超上限
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte{0}, maxResponseBytes+1))
	}))
	defer srv.Close()
	if _, err := (DefaultTransport{BaseURL: srv.URL}).Send(RequestDraft{Method: "GET", Path: "/x"}); err == nil {
		t.Error("超限响应应失败")
	} else if err.(*Error).Code != CodeProtocol {
		t.Errorf("超限错误类 = %s", err.(*Error).Code)
	}
}

// 非 2xx 状态：网关错误信封仍走 F6 校验（此处无签名头 → 明确失败），
// 状态码原样透传给调用方判断。
func TestClient_Do_Non2xxPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"code":"OP_GW_1017"}`))
	}))
	defer srv.Close()

	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = DefaultTransport{BaseURL: srv.URL}
	client, _ := NewClient(cfg)
	_, resp, err := client.Do("POST", "/p", []byte("x"), Level0)
	if err == nil {
		t.Fatal("无签名响应应报错")
	}
	if resp.StatusCode != 429 {
		t.Errorf("状态码应透传: %d", resp.StatusCode)
	}
}
