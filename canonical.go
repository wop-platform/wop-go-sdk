package wop

import (
	"sort"
	"strings"
)

// CanonicalHeaders 构造规范标头（F2）：名称 lowercase + TrimAll + urlencode，
// 值 TrimAll + urlencode，按名称 ASCII 升序，行间 '\n' 连接，尾行不加 '\n'。
func CanonicalHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	sorted := make(map[string]string, len(headers))
	names := make([]string, 0, len(headers))
	for name, value := range headers {
		key := strings.ToLower(TrimAll(name))
		if _, exists := sorted[key]; !exists {
			names = append(names, key)
		}
		sorted[key] = TrimAll(value)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, name := range names {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(URLEncodeJava(name))
		b.WriteByte(':')
		b.WriteString(URLEncodeJava(sorted[name]))
	}
	return b.String()
}

// CanonicalRequest 组装 5 段规范请求（F2）：
//
//	authString\nhttpRequestMethod\ncanonicalURI\ncanonicalQueryString\ncanonicalHeaders
//
// POST 的 canonicalQueryString 为空串，分隔空行不可省略；
// method 统一大写。Go string 零值即 ""，天然等价网关 build 的 null→"" 合并。
func CanonicalRequest(authString, method, canonicalURI, canonicalQueryString, canonicalHeaders string) string {
	return authString + "\n" +
		strings.ToUpper(strings.TrimSpace(method)) + "\n" +
		canonicalURI + "\n" +
		canonicalQueryString + "\n" +
		canonicalHeaders
}
