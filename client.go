package wop

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Level 是报文加密级别：L0 明文、L2 全文数字信封。
type Level string

const (
	Level0 Level = "L0"
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
	// SecurityReq 算法套件标识（如 WOP-RSA3072-SHA256）。
	SecurityReq string
	// MerchantPrivateKey 商户私钥（加签 / L2 入站解包）。
	MerchantPrivateKey string
	// PlatformPublicKey 平台公钥（验签 / L2 出站 DEK 包装）。
	PlatformPublicKey string
	// GatewayBaseURL 网关基地址（DefaultTransport 使用）。
	GatewayBaseURL string
	// ExpiredSeconds 出站签名有效时长（秒），0 → 默认 1800，上限 86400。
	ExpiredSeconds int64
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
		return nil, newError(CodeConfig, "AppKey 为空")
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
		return nil, newError(CodeConfig, "ExpiredSeconds 超出允许范围 (0, %d]", SignExpiredSecondsMax)
	}

	c := &Client{
		suite:          suite,
		appKey:         cfg.AppKey,
		expiredSeconds: expired,
		transport:      cfg.Transport,
		baseURL:        strings.TrimRight(cfg.GatewayBaseURL, "/"),
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
		c.transport = DefaultTransport{HTTPClient: &http.Client{}}
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

// BuildRequest 构造已签名（L2 时已加密）的请求草稿（spec §2 buildRequest）。
// 纯计算、零网络 IO；除 CSPRNG 值外同输入同输出。
func (c *Client) BuildRequest(method, path string, body []byte, level Level, opts ...RequestOption) (RequestDraft, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return RequestDraft{}, newError(CodeConfig, "HTTP method 为空")
	}
	if path == "" {
		return RequestDraft{}, newError(CodeConfig, "请求 path 为空")
	}

	options := RequestOptions{}
	for _, opt := range opts {
		opt(&options)
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
			return RequestDraft{}, newError(CodeConfig, "nonce 生成失败：%v", err)
		}
		headers[HeaderNonce] = hex.EncodeToString(nonceBytes)
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
		return RequestDraft{}, newError(CodeConfig, "未知加密级别 %q（支持 L0/L2）", string(level))
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

	signature, err := signMessage(c.suite, &c.merchantPriv, []byte(canonical), random)
	if err != nil {
		return RequestDraft{}, err
	}

	names := make([]string, 0, len(signedMap))
	for name := range signedMap {
		names = append(names, name)
	}
	sortStrings(names)
	headers[HeaderSign] = buildSignHeader(c.suite.SecurityReq(), c.expiredSeconds, names, signature)

	return RequestDraft{Method: method, Path: path, Headers: headers, WireBody: wireBody}, nil
}

// sealEnvelope 构造 L2 数字信封：CSPRNG CEK + IV（I4：IV 生成点唯一）→
// 套件报文策略全文加密 → JSON 信封 → 平台公钥包装 DEK。
func (c *Client) sealEnvelope(plaintext []byte, random io.Reader) (wireBody []byte, encryptHeader string, err error) {
	cek := make([]byte, c.suite.cekLen())
	if _, err := io.ReadFull(random, cek); err != nil {
		return nil, "", newError(CodeConfig, "CEK 生成失败：%v", err)
	}
	iv := make([]byte, gcmIVLen)
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, "", newError(CodeConfig, "IV 生成失败：%v", err)
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
// VerifyResult 同时返回完整判定。
func (c *Client) Do(method, path string, body []byte, level Level, opts ...RequestOption) (VerifyResult, TransportResponse, error) {
	draft, err := c.BuildRequest(method, path, body, level, opts...)
	if err != nil {
		return VerifyResult{}, TransportResponse{}, err
	}
	resp, err := c.transport.Send(draft)
	if err != nil {
		return VerifyResult{}, TransportResponse{}, err
	}
	res := c.VerifyResponse(method, path, resp.Headers, resp.Body)
	if !res.OK {
		return res, resp, &Error{Code: res.Code, Message: res.Reason}
	}
	return res, resp, nil
}
