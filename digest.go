package wop

import (
	"crypto/sha256"
	"crypto/subtle"
	"regexp"
	"strings"

	"github.com/emmansun/gmsm/sm3"
)

// digestWirePattern 钉死 D2 值结构：<sha-256|sm3> + 恰一空格 + 64 位小写 hex。
// 多余空白拒绝而非容忍（canonical header 值原样参与签名，容忍型解析 = 漂移温床）。
var digestWirePattern = regexp.MustCompile(`^(sha-256|sm3) [0-9a-f]{64}$`)

// Digest 按套件族计算摘要（④）：RSA 族 → SHA-256，SM2 族 → SM3（I5）。
func (s Suite) Digest(data []byte) []byte {
	if s.IsSM2() {
		sum := sm3.Sum(data)
		return sum[:]
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// DigestHeaderValue 组装 x-wop-content-digest 线上值：
// 算法标记 + 恰一空格 + 小写 hex（D2）。摘要对象 = data 原始字节
// （L2 时即密文载体，不摘明文）。
func DigestHeaderValue(s Suite, data []byte) string {
	return s.DigestTag() + " " + LowerHex(s.Digest(data))
}

// ParseContentDigest 严格解析 digest 头值，返回 (tag, hex)。
// 结构非法（双空格、大写、长度不符、未支持 tag 等）→ 协议类明确错误。
func ParseContentDigest(value string) (tag, hexSum string, err error) {
	if !digestWirePattern.MatchString(value) {
		return "", "", newError(CodeProtocol,
			"x-wop-content-digest 格式非法：须为 <sha-256|sm3> + 恰一空格 + 64 位小写 hex")
	}
	tag, hexSum, _ = strings.Cut(value, " ") // 正则已钉死恰一空格
	return tag, hexSum, nil
}

// ValidateContentDigestHeader 结构 + 套件族耦合校验（D2/I5，不含值比对；
// 与网关 ContentDigestHeader.validate 对齐，formatRules 消费口径）。
func ValidateContentDigestHeader(s Suite, headerValue string) error {
	tag, _, err := ParseContentDigest(headerValue)
	if err != nil {
		return err
	}
	if tag != s.DigestTag() {
		return newError(CodeProtocol,
			"x-wop-content-digest 标签 %q 与套件 %s 族不符（跨族拒绝）", tag, s.SecurityReq())
	}
	return nil
}

// ValidateContentDigest 复核线上报文摘要：结构（D2）→ 套件族耦合（I5）→ 值比对。
// 摘要不匹配返回完整性类明确错误（CodeDigestMismatch）。
func ValidateContentDigest(s Suite, headerValue string, wireBody []byte) error {
	tag, hexSum, err := ParseContentDigest(headerValue)
	if err != nil {
		return err
	}
	if tag != s.DigestTag() {
		return newError(CodeProtocol,
			"x-wop-content-digest 标签 %q 与套件 %s 族不符（跨族拒绝）", tag, s.SecurityReq())
	}
	computed := LowerHex(s.Digest(wireBody))
	if subtle.ConstantTimeCompare([]byte(computed), []byte(hexSum)) != 1 {
		return newError(CodeDigestMismatch, "x-wop-content-digest 与线上报文字节不匹配")
	}
	return nil
}
