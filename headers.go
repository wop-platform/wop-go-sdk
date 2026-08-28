package wop

// 协议 Header 名称（x-wop- 前缀，与网关 GatewayConstants 对齐）。
const (
	HeaderAppKey        = "x-wop-appkey"
	HeaderSign          = "x-wop-sign"
	HeaderContentDigest = "x-wop-content-digest"
	HeaderTimestamp     = "x-wop-timestamp"
	HeaderNonce         = "x-wop-nonce"
	HeaderEncrypt       = "x-wop-encrypt"
)

// 签名协议常量（spec §7 / 网关 GatewayConstants）。
const (
	// SignProtocolVersion 签名协议版本。
	SignProtocolVersion = "v1"
	// SignExpiredSecondsDefault 出站签名默认有效时长（秒）。
	SignExpiredSecondsDefault = int64(1800)
	// SignExpiredSecondsMax expiredSeconds 允许上限（秒），防超大窗口拉长重放风险。
	SignExpiredSecondsMax = int64(86400)
)
