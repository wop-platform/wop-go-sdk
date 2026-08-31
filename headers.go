package wop

// 协议 Header 名称（x-wop- 前缀，与网关 GatewayConstants 对齐）。
const (
	// HeaderAppKey 应用唯一标识头。
	HeaderAppKey = "x-wop-appkey"
	// HeaderSign 结构化签名头。
	HeaderSign = "x-wop-sign"
	// HeaderContentDigest 报文摘要头。
	HeaderContentDigest = "x-wop-content-digest"
	// HeaderTimestamp 请求时间戳头。
	HeaderTimestamp = "x-wop-timestamp"
	// HeaderNonce 防重放随机数头。
	HeaderNonce = "x-wop-nonce"
	// HeaderEncrypt L2 数字信封元数据头。
	HeaderEncrypt = "x-wop-encrypt"
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
