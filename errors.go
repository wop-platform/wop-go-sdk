// Package wop 是 WOP 网关商户侧官方 Go SDK：封装协议核心（套件解析、
// canonicalRequest、结构化签名、content-digest、L2 数字信封、验签解密）
// 与 HTTP 适配层，商户无需理解线上字节格式即可安全对接网关。
//
// 协议真源：gtsp-wop-gateway/docs/crypto-strategy-spec.md（v0.3-reviewed）
// 与 docs/wop-sdk-spec.md（v1.0-ratified）。全部二进制线上编码为
// base64url 无填充（拒收 '='），十六进制统一小写。
//
// 对外错误模糊化纪律（I7）：验签与解密失败的错误信息不区分原因细节
// （GCM tag 失败、密钥不符等），详细原因仅内部日志级别可见；配置类与
// 协议格式类错误语义明确，便于商户集成自查。
package wop

import "fmt"

// ErrorCode 是稳定的公共错误码契约（商户可编程处理）。
// 分类依据 crypto-strategy-spec §10.2：鉴权前可判定的公开协议知识 → 明确；
// 依赖密钥参与的判定 → 模糊（防 padding-oracle 式信息泄露）。
type ErrorCode string

const (
	// CodeConfig 配置类（明确）：密钥缺失、密钥解析失败、密钥与套件不符。
	CodeConfig ErrorCode = "CONFIG"
	// CodeSuiteParse 解析类（明确）：securityReq 空值/格式/前缀错误。
	CodeSuiteParse ErrorCode = "SUITE_PARSE"
	// CodeSuiteUnsupported 支持类（明确）：算法不在支持列表、跨族组合、长度非法。
	CodeSuiteUnsupported ErrorCode = "SUITE_UNSUPPORTED"
	// CodeProtocol 协议格式类（明确）：x-wop-sign / digest 头 / L2 信封结构非法。
	CodeProtocol ErrorCode = "PROTOCOL"
	// CodeDigestMismatch 完整性类（明确）：摘要与线上报文字节不符（D2）。
	CodeDigestMismatch ErrorCode = "DIGEST_MISMATCH"
	// CodeVerifyFailed 验签类（模糊）：签名验证失败，对外不区分原因（I7）。
	CodeVerifyFailed ErrorCode = "VERIFY_FAILED"
	// CodeDecryptFailed 解密类（模糊）：DEK 解包或 GCM 解密失败，对外不区分原因（I7）。
	CodeDecryptFailed ErrorCode = "DECRYPT_FAILED"
	// CodeAlgMismatch 一致性类（明确）：dek alg 与套件族不符（公开映射知识，I3 允许提前拒）。
	CodeAlgMismatch ErrorCode = "ALG_MISMATCH"
)

// I7 模糊化固定文案：验签/解密失败对外仅此二句，不携带任何细节。
const (
	verifyFuzzyMessage  = "签名验证失败"
	decryptFuzzyMessage = "解密失败"
)

// Error 是 SDK 的统一错误模型：Code 可编程处理，Message 为对外语义。
// 验签/解密类错误的 Message 恒为固定模糊文案。
type Error struct {
	Code    ErrorCode
	Message string
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	return fmt.Sprintf("wop: [%s] %s", e.Code, e.Message)
}

// newError 构造明确类错误（配置/协议/解析等，message 可含细节）。
func newError(code ErrorCode, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// fuzzyError 构造模糊类错误（验签/解密，I7：文案钉死，细节不外泄）。
func fuzzyError(code ErrorCode) *Error {
	msg := verifyFuzzyMessage
	if code == CodeDecryptFailed {
		msg = decryptFuzzyMessage
	}
	return &Error{Code: code, Message: msg}
}
