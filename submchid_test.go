package wop

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// verifySubMchSignature 回环验签：按 signedHeaders 重建 canonical，用商户公钥验签。
func verifySubMchSignature(t *testing.T, client *Client, draft RequestDraft, pubB64 string) {
	t.Helper()
	parsed, err := ParseSignHeader(draft.Headers[HeaderSign])
	if err != nil {
		t.Fatalf("解析签名头失败: %v", err)
	}
	pub := &pubKey{}
	if pub.rsa, err = parseRSAPublicKey(pubB64); err != nil {
		t.Fatalf("解析商户公钥失败: %v", err)
	}
	signedMap := map[string]string{}
	for _, h := range parsed.signedHeaders {
		signedMap[h] = draft.Headers[h]
	}
	canonical := CanonicalRequest(parsed.authString(), draft.Method, draft.Path, "",
		CanonicalHeaders(signedMap))
	if err := verifyMessage(client.suite, pub, []byte(canonical), parsed.signature); err != nil {
		t.Fatalf("子商户头入签后回环验签失败: %v", err)
	}
}

// TestSubMchIDHeaderSigned ISV D-13：存在即入签，且签名覆盖该头。
func TestSubMchIDHeaderSigned(t *testing.T) {
	v := loadGoldenVectors(t)
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		body []byte
		lvl  Level
		want []string
	}{
		{
			name: "L0 有 body",
			body: []byte(`{"k":1}`),
			lvl:  Level0,
			want: []string{HeaderAppKey, HeaderContentDigest, HeaderNonce, HeaderSubMchID, HeaderTimestamp},
		},
		{
			name: "L0 无 body",
			body: nil,
			lvl:  Level0,
			want: []string{HeaderAppKey, HeaderNonce, HeaderSubMchID, HeaderTimestamp},
		},
		{
			name: "L2 信封",
			body: []byte(`{"amount":1}`),
			lvl:  Level2,
			want: []string{HeaderAppKey, HeaderContentDigest, HeaderEncrypt, HeaderNonce, HeaderSubMchID, HeaderTimestamp},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			draft, err := client.BuildRequest("POST", "/p", tc.body, tc.lvl,
				WithTimestamp(1755900000000), WithNonce("n"), WithRequestID("req-001"),
				WithSubMchID("PLF-SUB-001"))
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if got := draft.Headers[HeaderSubMchID]; got != "PLF-SUB-001" {
				t.Fatalf("%s = %q, want PLF-SUB-001", HeaderSubMchID, got)
			}
			parsed, err := ParseSignHeader(draft.Headers[HeaderSign])
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed.signedHeaders, tc.want) {
				t.Fatalf("signedHeaders = %v, want %v", parsed.signedHeaders, tc.want)
			}
			for _, h := range parsed.signedHeaders {
				if h == HeaderRequestId {
					t.Fatalf("x-wop-request-id 不得进入 signedHeaders")
				}
			}
			verifySubMchSignature(t, client, draft, v.Keys.RSA3072.PublicSpkiB64)
		})
	}
}

// TestSubMchIDTrim ISV D-13：首尾空白 trim 后上行。
func TestSubMchIDTrim(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	draft, err := client.BuildRequest("GET", "/p", nil, Level0,
		WithTimestamp(1), WithNonce("n"), WithSubMchID("  PLF-SUB-001  "))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := draft.Headers[HeaderSubMchID]; got != "PLF-SUB-001" {
		t.Fatalf("%s = %q, want PLF-SUB-001（trim 后）", HeaderSubMchID, got)
	}
}

// TestSubMchIDAbsentZeroRegression AC-20：不传/空白 = 应用自身身份，头缺席且签名与旧行为逐字节一致。
func TestSubMchIDAbsentZeroRegression(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"k":1}`)
	baseline, err := client.BuildRequest("POST", "/p", body, Level0,
		WithTimestamp(1), WithNonce("n"), WithRequestID("req-001"))
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	for _, blank := range []string{"", "   "} {
		draft, err := client.BuildRequest("POST", "/p", body, Level0,
			WithTimestamp(1), WithNonce("n"), WithRequestID("req-001"), WithSubMchID(blank))
		if err != nil {
			t.Fatalf("blank %q: %v", blank, err)
		}
		if _, has := draft.Headers[HeaderSubMchID]; has {
			t.Fatalf("blank %q: 子商户头应缺席", blank)
		}
		if !reflect.DeepEqual(baseline.Headers, draft.Headers) {
			t.Fatalf("blank %q: 头集合与旧行为不一致\n got %v\nwant %v", blank, draft.Headers, baseline.Headers)
		}
	}

	// L2 因 CSPRNG CEK/IV 不做跨调用逐字节比较，仅断言头缺席。
	l2, err := client.BuildRequest("POST", "/p", body, Level2,
		WithTimestamp(1), WithNonce("n"), WithSubMchID("   "))
	if err != nil {
		t.Fatalf("L2 blank: %v", err)
	}
	if _, has := l2.Headers[HeaderSubMchID]; has {
		t.Fatal("L2 blank: 子商户头应缺席")
	}
}

// TestSubMchIDValidation ISV D-13：可打印 ASCII、无内部空白、trim 后 ≤128 字符。
func TestSubMchIDValidation(t *testing.T) {
	client, err := NewClient(testConfig(t, "WOP-RSA3072-SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	build := func(id string) (RequestDraft, error) {
		return client.BuildRequest("GET", "/p", nil, Level0,
			WithTimestamp(1), WithNonce("n"), WithSubMchID(id))
	}

	t.Run("边界128允许129拒绝", func(t *testing.T) {
		ok, err := build(strings.Repeat("a", 128))
		if err != nil {
			t.Fatalf("128 字符应通过: %v", err)
		}
		if ok.Headers[HeaderSubMchID] != strings.Repeat("a", 128) {
			t.Fatalf("128 字符值被改写")
		}
		_, err = build(strings.Repeat("a", 129))
		if err == nil || !strings.Contains(err.Error(), "实际 129") {
			t.Fatalf("129 字符应拒绝且消息含实际值, got %v", err)
		}
		if we, ok := err.(*Error); !ok || we.Code != CodeConfiguration {
			t.Errorf("129 字符: err = %v, want configuration", err)
		}
	})

	t.Run("控制字符trim前扫描即拒", func(t *testing.T) {
		for _, bad := range []string{"a\nb", "a\rb", "a\x00b", "a\tb", "\tsub", "sub\t", "a\x7fb"} {
			_, err := build(bad)
			if err == nil {
				t.Fatalf("subMchId %q 含控制字符应拒绝", bad)
			}
			we, ok := err.(*Error)
			if !ok || we.Code != CodeConfiguration {
				t.Errorf("subMchId %q: err = %v, want configuration", bad, err)
			}
			if !strings.Contains(err.Error(), "可打印 ASCII") {
				t.Errorf("subMchId %q: 消息须含「可打印 ASCII」，got %q", bad, err.Error())
			}
		}
	})

	t.Run("非ASCII拒绝且不回显原值", func(t *testing.T) {
		_, err := build("PLF中文")
		if err == nil {
			t.Fatal("非 ASCII subMchId 应拒绝")
		}
		if !strings.Contains(err.Error(), "可打印 ASCII") {
			t.Errorf("消息须含「可打印 ASCII」，got %q", err.Error())
		}
		if we, ok := err.(*Error); !ok || we.Code != CodeConfiguration {
			t.Errorf("非 ASCII: err = %v, want configuration", err)
		}
		if strings.Contains(err.Error(), "中文") {
			t.Errorf("错误消息不得回显原值，got %q", err.Error())
		}
	})

	t.Run("内部空白拒绝", func(t *testing.T) {
		for _, bad := range []string{"PLF SUB", "PLF  SUB"} {
			_, err := build(bad)
			if err == nil || !strings.Contains(err.Error(), "内部空白") {
				t.Errorf("subMchId %q 应因内部空白拒绝, got %v", bad, err)
			}
			if we, ok := err.(*Error); !ok || we.Code != CodeConfiguration {
				t.Errorf("subMchId %q: err = %v, want configuration", bad, err)
			}
		}
	})

	t.Run("可打印ASCII边界允许", func(t *testing.T) {
		d, err := build("!~")
		if err != nil {
			t.Fatalf("!~ 应通过: %v", err)
		}
		if d.Headers[HeaderSubMchID] != "!~" {
			t.Fatalf("!~ 被改写: %q", d.Headers[HeaderSubMchID])
		}
	})
}

// TestSubMchIDExecutePassthrough Execute/Do 透传：选项经一站式调用进入签名头。
func TestSubMchIDExecutePassthrough(t *testing.T) {
	var captured RequestDraft
	cfg := testConfig(t, "WOP-RSA3072-SHA256")
	cfg.Transport = TransportFunc(func(d RequestDraft) (TransportResponse, error) {
		captured = d
		return TransportResponse{StatusCode: http.StatusOK, Headers: http.Header{}, Body: nil}, nil
	})
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 空响应必验签失败，但请求已构造并发送——只断言捕获的 draft。
	_, err = client.Execute("POST", "/p", []byte(`{}`), Level0,
		WithTimestamp(1), WithNonce("n"), WithRequestID("req-001"), WithSubMchID("PLF-SUB-001"))
	if err == nil {
		t.Fatal("空响应应返回验签错误")
	}
	if got := captured.Headers[HeaderSubMchID]; got != "PLF-SUB-001" {
		t.Fatalf("%s = %q, want PLF-SUB-001", HeaderSubMchID, got)
	}
	parsed, err := ParseSignHeader(captured.Headers[HeaderSign])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range parsed.signedHeaders {
		if h == HeaderSubMchID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Execute 路径子商户头未入签: %v", parsed.signedHeaders)
	}
}
