package wop

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"
)

// Level 是报文加密级别：L0 明文、L2 全文数字信封。
type Level string

const (
	// Level0 明文级别（L0）：不上数字信封，报文原样传输。
	Level0 Level = "L0"
	// Level2 全文数字信封级别（L2）：随机 CEK + GCM 加密全文，CEK 经平台公钥包装。
	Level2 Level = "L2"
)

// RequestDraft 是协议核心产出的待发送请求：商户可直接消费自带 HTTP 栈，
// 或交给本 SDK Transport 发送。
type RequestDraft struct {
	Method   string
	Path     string
	Headers  map[string]string
	WireBody []byte
}

// Config 商户接入配置。密钥材料为字符串（PEM 或 Base64 单行，D12）。
type Config struct {
	// AppKey 平台分配的应用唯一标识。
	AppKey string
	// SecurityReq 算法套件标识（如 WOP-RSA3072-SHA256）；JSON 字段名为 suite。
	SecurityReq string
	// MerchantPrivateKey 商户私钥（加签 / L2 入站解包）。
	MerchantPrivateKey string
	// PlatformPublicKey 平台公钥（验签 / L2 出站 DEK 包装）。
	PlatformPublicKey string
	// ServerRoot 主网关根地址（HTTPS 绝对 URL，含 context-path）。
	ServerRoot string
	// GatewayBaseURL 网关基地址（ServerRoot 的兼容别名，ServerRoot 优先）。
	GatewayBaseURL string
	// BackupServerRoots 备用网关根地址（有序，仅全局；Failover P2）。
	BackupServerRoots []string
	// ExpiredSeconds 出站签名有效时长（秒），0 → 默认 1800，上限 86400。
	ExpiredSeconds int64
	// HTTPClient 全局 HTTP 客户端参数。
	HTTPClient HTTPClientSettings
	// Transport 发送适配器；nil → DefaultTransport（http.Client 默认实例）。
	Transport Transport
}

// Client 是线程安全的 WOP 协议客户端：BuildRequest 纯函数产线，
// VerifyResponse/VerifyCallback 消费 F6 管线，Do 一站式发送+校验。
type Client struct {
	suite          Suite
	appKey         string
	expiredSeconds int64
	merchantPriv   privKey
	platformPub    pubKey
	transport      Transport
	baseURL        string
}

// NewClient 解析并校验配置（套件原子装配 + 密钥格式/位数校验，错误均明确）。
func NewClient(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.AppKey) == "" {
		return nil, newError(CodeConfiguration, "AppKey 为空")
	}
	suite, err := ParseSuite(cfg.SecurityReq)
	if err != nil {
		return nil, err
	}
	expired := cfg.ExpiredSeconds
	if expired == 0 {
		expired = SignExpiredSecondsDefault
	}
	if expired < 0 || expired > SignExpiredSecondsMax {
		return nil, newError(CodeConfiguration, "ExpiredSeconds 超出允许范围 (0, %d]", SignExpiredSecondsMax)
	}

	baseURL := strings.TrimSpace(cfg.ServerRoot)
	if baseURL == "" {
		baseURL = strings.TrimSpace(cfg.GatewayBaseURL)
	}
	c := &Client{
		suite:          suite,
		appKey:         cfg.AppKey,
		expiredSeconds: expired,
		transport:      cfg.Transport,
		baseURL:        strings.TrimRight(baseURL, "/"),
	}

	switch {
	case suite.IsSM2():
		if c.merchantPriv.sm2, err = parseSM2PrivateKey(cfg.MerchantPrivateKey); err != nil {
			return nil, err
		}
		if c.platformPub.sm2, err = parseSM2PublicKey(cfg.PlatformPublicKey); err != nil {
			return nil, err
		}
	default:
		if c.merchantPriv.rsa, err = parseRSAPrivateKey(cfg.MerchantPrivateKey); err != nil {
			return nil, err
		}
		if c.platformPub.rsa, err = parseRSAPublicKey(cfg.PlatformPublicKey); err != nil {
			return nil, err
		}
		if err := validateRSAKeySize(suite, c.merchantPriv.rsa); err != nil {
			return nil, err
		}
		if err := validateRSASize(suite, c.platformPub.rsa.N.BitLen()); err != nil {
			return nil, err
		}
	}

	if c.transport == nil {
		c.transport = DefaultTransport{
			HTTPClient: newDefaultHTTPClient(cfg.HTTPClient),
			BaseURL:    c.baseURL,
		}
	}
	return c, nil
}

// Suite 返回已装配的算法套件（只读视图）。
func (c *Client) Suite() Suite { return c.suite }

// RequestOptions 是 BuildRequest 的可选项（测试确定性钩子）。
type RequestOptions struct {
	// TimestampMs 毫秒 Unix 时间戳；0 → 当前时间。
	TimestampMs int64
	// Nonce 防重放随机串；空 → CSPRNG 生成 32 位 hex。
	Nonce string
	// Random 随机源（nonce/CEK/IV 顺序消费）；nil → crypto/rand。
	Random io.Reader
	// RequestID 商户请求标识（wop-specs 附录 I：x-wop-request-id 透传头，恒不入签；
	// 须为不含个人数据的不透明关联标识）。空/空白 → 缺省生成 UUID 去连字符（头恒存在）；
	// 显式传值 trim 后原值上行；控制字符（trim 前扫描）与超长（trim 后 UTF-8 字节 > 128）即拒。
	RequestID string
	// SubMchID ISV 子商户身份（ISV D-13）：值 = 子商户 plf_co_id，签名前写入
	// x-wop-sub-mch-id 并自动纳入 signedHeaders；空/空白 = 应用自身身份（头缺席，AC-20）。
	// 须为可打印 ASCII、无内部空白、trim 后 ≤ 128 字符，违规构造即拒。
	SubMchID string
}

// RequestOption 单个选项。
type RequestOption func(*RequestOptions)

// WithTimestamp 固定毫秒时间戳（重放/联调用）。
func WithTimestamp(ms int64) RequestOption {
	return func(o *RequestOptions) { o.TimestampMs = ms }
}

// WithNonce 固定 nonce（重放/联调用）。
func WithNonce(nonce string) RequestOption {
	return func(o *RequestOptions) { o.Nonce = nonce }
}

// WithRandom 注入确定性随机源（联调用；生产禁用——IV 复用即 I4 违规）。
func WithRandom(r io.Reader) RequestOption {
	return func(o *RequestOptions) { o.Random = r }
}

// WithRequestID 显式指定商户请求标识（附录 I 透传头；空/空白 → 缺省生成）。
func WithRequestID(id string) RequestOption {
	return func(o *RequestOptions) { o.RequestID = id }
}

// WithSubMchID 指定 ISV 子商户身份（ISV D-13；值 = plf_co_id；空/空白 → 头缺席）。
func WithSubMchID(id string) RequestOption {
	return func(o *RequestOptions) { o.SubMchID = id }
}

// BuildRequest 构造已签名（L2 时已加密）的请求草稿（spec §2 buildRequest）。
// 纯计算、零网络 IO；除 CSPRNG 值外同输入同输出。
func (c *Client) BuildRequest(method, path string, body []byte, level Level, opts ...RequestOption) (RequestDraft, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return RequestDraft{}, newError(CodeConfiguration, "HTTP method 为空")
	}
	if err := validateAPIPath(path); err != nil {
		return RequestDraft{}, err
	}

	options := RequestOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	// 附录 I/I2：requestId 构造即校验（fail-fast，不延迟到发送前）
	resolvedRequestID, hasRequestID, err := resolveRequestID(options.RequestID)
	if err != nil {
		return RequestDraft{}, err
	}
	// ISV D-13：subMchId 同样构造即校验
	resolvedSubMchID, hasSubMchID, err := resolveSubMchID(options.SubMchID)
	if err != nil {
		return RequestDraft{}, err
	}
	random := options.Random
	if random == nil {
		random = rand.Reader
	}
	timestamp := options.TimestampMs
	if timestamp == 0 {
		timestamp = time.Now().UnixMilli()
	}

	headers := map[string]string{
		HeaderAppKey:    c.appKey,
		HeaderTimestamp: strconv.FormatInt(timestamp, 10),
	}
	if options.Nonce != "" {
		headers[HeaderNonce] = options.Nonce
	} else {
		nonceBytes := make([]byte, 16)
		if _, err := io.ReadFull(random, nonceBytes); err != nil {
			return RequestDraft{}, newError(CodeConfiguration, "nonce 生成失败：%v", err)
		}
		headers[HeaderNonce] = hex.EncodeToString(nonceBytes)
	}
	// ISV D-13：签名前写入，signedHeaders 自动包含；缺席时头集合与旧行为完全一致
	if hasSubMchID {
		headers[HeaderSubMchID] = resolvedSubMchID
	}

	var wireBody []byte
	switch level {
	case Level0:
		wireBody = body
	case Level2:
		wire, encryptHeader, err := c.sealEnvelope(body, random)
		if err != nil {
			return RequestDraft{}, err
		}
		wireBody = wire
		headers[HeaderEncrypt] = encryptHeader
	default:
		return RequestDraft{}, newError(CodeConfiguration, "未知加密级别 %q（支持 L0/L2）", string(level))
	}

	// D2/D3/I1：有 body（wire 字节）必产 digest 且必入签名；无 body 缺席。
	if len(wireBody) > 0 {
		headers[HeaderContentDigest] = DigestHeaderValue(c.suite, wireBody)
	}

	signedMap := map[string]string{}
	for name, value := range headers {
		signedMap[name] = value
	}
	canonical := CanonicalRequest(
		SignProtocolVersion+"/"+strconv.FormatInt(c.expiredSeconds, 10), method, path, "",
		CanonicalHeaders(signedMap))

	// D14：出向签名 userId 必须 = x-wop-appkey 头值（= c.appKey），禁止静默回退默认值。
	signature, err := signMessage(c.suite, &c.merchantPriv, []byte(c.appKey), []byte(canonical), random)
	if err != nil {
		return RequestDraft{}, err
	}

	names := make([]string, 0, len(signedMap))
	for name := range signedMap {
		names = append(names, name)
	}
	sortStrings(names)
	headers[HeaderSign] = buildSignHeader(c.suite.SecurityReq(), c.expiredSeconds, names, signature)

	// requestId 透传头（附录 I）：在签名落盘**之后**写入，保证不在 signedHeaders 冻结清单中；
	// 商户未传（含 trim 后为空）→ 缺省生成，最终头恒存在
	if !hasRequestID {
		resolvedRequestID = requestIDGen()
	}
	headers[HeaderRequestId] = resolvedRequestID
	// 附录 I/I3 日志义务：出向构造点打印最终透传头值（非敏感，豁免脱敏），供网关 AccessLog 关联排查
	outboundLog.Printf("x-wop-request-id=%s %s %s", resolvedRequestID, method, path)

	return RequestDraft{Method: method, Path: path, Headers: headers, WireBody: wireBody}, nil
}

// sealEnvelope 构造 L2 数字信封：CSPRNG CEK + IV（I4：IV 生成点唯一）→
// 套件报文策略全文加密 → JSON 信封 → 平台公钥包装 DEK。
func (c *Client) sealEnvelope(plaintext []byte, random io.Reader) (wireBody []byte, encryptHeader string, err error) {
	cek := make([]byte, c.suite.cekLen())
	if _, err := io.ReadFull(random, cek); err != nil {
		return nil, "", newError(CodeConfiguration, "CEK 生成失败：%v", err)
	}
	iv := make([]byte, gcmIVLen)
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, "", newError(CodeConfiguration, "IV 生成失败：%v", err)
	}

	ciphertext, err := sealMessage(c.suite, plaintext, cek, iv)
	if err != nil {
		return nil, "", err
	}
	wireBody = wrapEncryptedBody(EncodeB64URL(ciphertext))

	wrapped, err := wrapDEKPayload(c.suite, &c.platformPub, []byte(buildDekPayload(c.suite.MessageAlgorithm(), cek, iv)), random)
	if err != nil {
		return nil, "", err
	}
	return wireBody, buildEncryptHeader(wrapped), nil
}

// sortStrings 原地升序排序 signedHeaders（小规模专用，见内注释）。
func sortStrings(s []string) {
	// 小切片插入排序足够（元素个数 ≤ 6）
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Do 一站式调用：BuildRequest → Transport.Send → VerifyResponse（F6）。
// 构建或发送失败返回错误；响应校验失败时 err 携带 wop.Error（Code 可编程处理），
// VerifyResult 同时返回完整判定。非 2xx 响应抛 GatewayResponseError（§7.5）。
func (c *Client) Do(method, path string, body []byte, level Level, opts ...RequestOption) (VerifyResult, TransportResponse, error) {
	return c.execute(method, path, body, level, opts...)
}

// Execute 一站式调用（spec execute 语义）：签名 → 发送 → 非 2xx 拦截 → 验签解密。
func (c *Client) Execute(method, path string, body []byte, level Level, opts ...RequestOption) (VerifyResult, error) {
	res, _, err := c.execute(method, path, body, level, opts...)
	return res, err
}

func (c *Client) execute(method, path string, body []byte, level Level, opts ...RequestOption) (VerifyResult, TransportResponse, error) {
	draft, err := c.BuildRequest(method, path, body, level, opts...)
	if err != nil {
		return VerifyResult{}, TransportResponse{}, err
	}
	resp, err := c.transport.Send(draft)
	if err != nil {
		return VerifyResult{}, TransportResponse{}, err
	}
	if !is2xx(resp.StatusCode) {
		return VerifyResult{}, resp, &GatewayResponseError{StatusCode: resp.StatusCode, Body: resp.Body}
	}
	res := c.VerifyResponse(method, path, resp.Headers, resp.Body)
	if !res.OK {
		return res, resp, &Error{Code: res.Code, Message: res.Reason}
	}
	return res, resp, nil
}
