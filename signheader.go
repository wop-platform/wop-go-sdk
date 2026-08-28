package wop

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// F3：结构化签名头 x-wop-sign。
// 格式：<securityReq> <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature>
// 示例：WOP-RSA3072-SHA256 v1/1800/x-wop-appkey;x-wop-nonce/pOVoj1mI...
// 解析与网关 SignHeaderParser 严格语义对齐（trim 容忍、v1 钉死、段数与范围校验）。

// signHeader 是解析后的结构化签名头。
type signHeader struct {
	securityReq     string
	protocolVersion string
	expiredSeconds  int64
	signedHeaders   []string
	signature       string
}

func (p signHeader) authString() string {
	return p.protocolVersion + "/" + strconv.FormatInt(p.expiredSeconds, 10)
}

// ParseSignHeader 严格解析 x-wop-sign 值；结构非法为协议类明确错误。
func ParseSignHeader(header string) (signHeader, error) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return signHeader{}, newError(CodeProtocol, "缺少 x-wop-sign 头")
	}
	sp := strings.IndexByte(trimmed, ' ')
	if sp <= 0 {
		return signHeader{}, newError(CodeProtocol, "x-wop-sign 格式错误：缺少 securityReq 与 authString 的空格分隔")
	}
	securityReq := trimmed[:sp]
	// 签名为 base64url（无 '/'），SplitN 4 段安全
	seg := strings.SplitN(strings.TrimSpace(trimmed[sp+1:]), "/", 4)
	if len(seg) != 4 {
		return signHeader{}, newError(CodeProtocol,
			"x-wop-sign 格式错误：应为 <protocolVersion>/<expiredSeconds>/<signedHeaders>/<signature>")
	}
	if seg[0] != SignProtocolVersion {
		return signHeader{}, newError(CodeProtocol, "不支持的签名协议版本 %q", seg[0])
	}
	expiredSeconds, err := strconv.ParseInt(seg[1], 10, 64)
	if err != nil {
		return signHeader{}, newError(CodeProtocol, "expiredSeconds 非法 %q", seg[1])
	}
	if expiredSeconds <= 0 || expiredSeconds > SignExpiredSecondsMax {
		return signHeader{}, newError(CodeProtocol, "expiredSeconds 超出允许范围 (0, %d]",
			SignExpiredSecondsMax)
	}
	signedHeaders := parseSignedHeaders(seg[2])
	if len(signedHeaders) == 0 {
		return signHeader{}, newError(CodeProtocol, "signedHeaders 为空")
	}
	if strings.TrimSpace(seg[3]) == "" {
		return signHeader{}, newError(CodeProtocol, "signature 为空")
	}
	return signHeader{
		securityReq:     securityReq,
		protocolVersion: seg[0],
		expiredSeconds:  expiredSeconds,
		signedHeaders:   signedHeaders,
		signature:       seg[3],
	}, nil
}

func parseSignedHeaders(raw string) []string {
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		name := strings.ToLower(strings.TrimSpace(p))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// buildSignHeader 组装 x-wop-sign 值（signedHeaders 须已排序去重）。
func buildSignHeader(securityReq string, expiredSeconds int64, signedHeaders []string, signature string) string {
	return securityReq + " " + SignProtocolVersion + "/" + strconv.FormatInt(expiredSeconds, 10) +
		"/" + strings.Join(signedHeaders, ";") + "/" + signature
}

// F5：加密指令头 x-wop-encrypt: L2;dek=<base64url>。

// buildEncryptHeader 组装 L2 加密指令头。
func buildEncryptHeader(dekB64u string) string {
	return "L2;dek=" + dekB64u
}

// parseEncryptHeader 解析加密指令头：仅支持 L2 且必带 dek；
// dek 段字符集前置校验（b64url 无填充，快速失败）。
func parseEncryptHeader(value string) (level string, dekB64u string, err error) {
	v := strings.TrimSpace(value)
	const prefix = "L2;dek="
	if !strings.HasPrefix(v, prefix) || len(v) <= len(prefix) {
		return "", "", newError(CodeProtocol, "x-wop-encrypt 须为 L2;dek=<base64url>")
	}
	dek := v[len(prefix):]
	if !isStrictB64URLChars(dek) {
		return "", "", newError(CodeProtocol, "x-wop-encrypt dek 段须为 base64url 无填充")
	}
	return "L2", dek, nil
}

// isStrictB64URLChars 校验仅含 URL 字母表字符（无 '='、无标准字母表字符）。
func isStrictB64URLChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// encryptedEnvelope 是 L2 线上信封 JSON。
type encryptedEnvelope struct {
	Encrypted string `json:"encrypted"`
}

// wrapEncryptedBody 将密文包裹为 {"encrypted":"<b64url>"} 线上体。
// b64url 字母表无需 JSON 转义，直接拼装（与 json.Marshal 输出逐字节一致）。
func wrapEncryptedBody(cipherB64u string) []byte {
	return []byte(`{"encrypted":"` + cipherB64u + `"}`)
}

// extractEncryptedBody 从线上体提取 encrypted 密文字段（容忍未知字段，与网关语义一致）。
func extractEncryptedBody(wireBody []byte) (string, error) {
	var env encryptedEnvelope
	if err := json.Unmarshal(wireBody, &env); err != nil {
		return "", newError(CodeProtocol, "L2 请求体不是合法 JSON 信封")
	}
	if env.Encrypted == "" {
		return "", newError(CodeProtocol, "L2 请求体缺少 encrypted 密文字段")
	}
	return env.Encrypted, nil
}

// headerValue 大小写不敏感取头值（http.Header.Get 已实现，显式包装便于统一调用）。
func headerValue(h http.Header, name string) string {
	return h.Get(name)
}
