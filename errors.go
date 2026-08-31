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

// ErrorCode 是公共错误码契约（商户可编程处理），取值必须来自
// wop-sdk-spec §2.2 闭集（小写 ASCII，跨语言恒定，禁止自造）。
// 闭集七值：configuration / parse / unsupported / integrity /
// consistency / signature / decrypt。
//
// 明确类（configuration/parse/unsupported/integrity/consistency）：
// 依赖公开协议知识、鉴权前可判定，Message 可含细节（D6 允许全等断言）。
// 模糊类（signature/decrypt）：依赖密钥参与的判定，Message 恒为固定
// 模糊文案（I7，防 padding-oracle 式信息泄露），禁止携带原因细节。
type ErrorCode string

const (
	// CodeConfiguration 配置类（明确）：appKey / 密钥材料缺失或非法、
	// securityReq 非法或跨族（F1）。
	CodeConfiguration ErrorCode = "configuration"
	// CodeParse 协议解析类（明确）：header / 信封 / 线上编码格式（D1/D3）。
	CodeParse ErrorCode = "parse"
	// CodeUnsupported 能力不支持类（明确）：合法套件但本 SDK 未实现
	// （如 TS/PHP 首版 SM，spec §1.2）。Go 已实现全部合法套件，
	// 无触发路径，保留枚举值以满足闭集完整性。
	CodeUnsupported ErrorCode = "unsupported"
	// CodeIntegrity 完整性类（明确）：digest 与线上报文字节不符（D2）。
	CodeIntegrity ErrorCode = "integrity"
	// CodeConsistency 一致性类（明确）：dek alg 与套件族不符
	// （公开映射知识，I3 允许提前拒）。
	CodeConsistency ErrorCode = "consistency"
	// CodeSignature 验签类（模糊）：签名验证失败，对外不区分原因（I7）。
	CodeSignature ErrorCode = "signature"
	// CodeDecrypt 解密类（模糊）：DEK 解包或 GCM 解密失败，
	// 对外不区分原因（I7）。
	CodeDecrypt ErrorCode = "decrypt"
)

// I7 模糊化固定文案：验签/解密失败对外仅此二句，不携带任何细节。
const (
	// verifyFuzzyMessage 验签失败对外固定文案（I7 模糊化）。
	verifyFuzzyMessage = "签名验证失败"
	// decryptFuzzyMessage 解密失败对外固定文案（I7 模糊化）。
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
	if code == CodeDecrypt {
		msg = decryptFuzzyMessage
	}
	return &Error{Code: code, Message: msg}
}
