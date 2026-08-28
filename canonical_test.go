package wop

import "testing"

// F2：规范标头 = 名称 lowercase+Trimall+urlencode，值 Trimall+urlencode，
// ASCII 升序，'\n' 连接，尾行不加 '\n'（与网关 CanonicalRequestBuilder 对齐）。
func TestCanonicalHeaders(t *testing.T) {
	got := CanonicalHeaders(map[string]string{
		"X-Wop-Nonce":  "abc def",
		"x-wop-appkey": "  key1  ",
	})
	want := "x-wop-appkey:key1\nx-wop-nonce:abc%20def"
	if got != want {
		t.Fatalf("CanonicalHeaders = %q, want %q", got, want)
	}

	if got := CanonicalHeaders(nil); got != "" {
		t.Errorf("nil map → %q, want empty", got)
	}

	// 值含 '+'：canonical 用 %2B（非表单 '+'）
	got = CanonicalHeaders(map[string]string{"a": "1+2"})
	if got != "a:1%2B2" {
		t.Errorf("plus handling: %q", got)
	}

	// 重复名称折叠（map 语义，与 Java TreeMap 覆盖一致）
	got = CanonicalHeaders(map[string]string{"A": "1", "a": "2"})
	if got != "a:2" {
		t.Errorf("case fold: %q", got)
	}
}

// F2：canonicalRequest = 5 段 '\n' 连接；POST 的 canonicalQueryString
// 为空串但分隔空行不可省略。
func TestCanonicalRequest(t *testing.T) {
	hdrs := CanonicalHeaders(map[string]string{"x-wop-nonce": "n1"})
	got := CanonicalRequest("v1/1800", "post", "/gateway/logistics.order.query", "", hdrs)
	want := "v1/1800\nPOST\n/gateway/logistics.order.query\n\nx-wop-nonce:n1"
	if got != want {
		t.Fatalf("CanonicalRequest = %q, want %q", got, want)
	}

	// 空段（无已签名头）时空行仍在
	got = CanonicalRequest("v1/1800", "GET", "/p", "", "")
	if got != "v1/1800\nGET\n/p\n\n" {
		t.Errorf("empty headers: %q", got)
	}

	// method 统一大写（先 trim）
	got = CanonicalRequest("v1/1", "  delete ", "/p", "", "")
	if want := "v1/1\nDELETE\n/p\n\n"; got != want {
		t.Errorf("method normalize: %q, want %q", got, want)
	}
}
