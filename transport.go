package wop

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Transport 是可插拔 HTTP 适配层（spec §1.1 Q1：协议核心纯函数，传输可替换）。
// 商户自带栈时直接消费 RequestDraft，无需本接口。
type Transport interface {
	Send(RequestDraft) (TransportResponse, error)
}

// TransportResponse 是适配层归一化的响应。
type TransportResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// DefaultTransport 默认 net/http 适配器。
type DefaultTransport struct {
	// HTTPClient 为 nil 时使用 http.DefaultClient。
	HTTPClient *http.Client
	// BaseURL 网关基地址；draft.Path 拼接其上。为空时 draft.Path 须为完整 URL。
	BaseURL string
}

// maxResponseBytes 响应体读取上限（10MB 线上体上限 + 信封膨胀余量，防失控读）。
const maxResponseBytes = 11 << 20

// Send 实现 Transport：构建 http.Request 并发送，读取响应体。
func (t DefaultTransport) Send(d RequestDraft) (TransportResponse, error) {
	client := t.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	target := strings.TrimRight(t.BaseURL, "/") + d.Path
	parsed, err := url.Parse(target)
	if err != nil || !parsed.IsAbs() {
		return TransportResponse{}, newError(CodeConfiguration, "请求地址非法：%s", target)
	}

	req, err := http.NewRequest(d.Method, target, bytes.NewReader(d.WireBody))
	if err != nil {
		return TransportResponse{}, newError(CodeConfiguration, "构建 HTTP 请求失败：%v", err)
	}
	for name, value := range d.Headers {
		req.Header.Set(name, value)
	}
	if len(d.WireBody) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return TransportResponse{}, newError(CodeConfiguration, "HTTP 发送失败：%v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return TransportResponse{}, newError(CodeConfiguration, "读取响应体失败：%v", err)
	}
	if len(body) > maxResponseBytes {
		return TransportResponse{}, newError(CodeParse, "响应体超过 %d 字节上限", maxResponseBytes)
	}
	return TransportResponse{StatusCode: resp.StatusCode, Headers: resp.Header, Body: body}, nil
}

// TransportFunc 函数适配器（测试/自定义发送逻辑）。
type TransportFunc func(RequestDraft) (TransportResponse, error)

// Send 实现 Transport。
func (f TransportFunc) Send(d RequestDraft) (TransportResponse, error) { return f(d) }

// RoundTripperTransport 把任意 http.RoundTripper 桥接为 Transport
// （商户复用自带栈的连接池/中间件；baseURL 语义同 DefaultTransport）。
func RoundTripperTransport(rt http.RoundTripper, baseURL string) Transport {
	return TransportFunc(func(d RequestDraft) (TransportResponse, error) {
		return DefaultTransport{HTTPClient: &http.Client{Transport: rt}, BaseURL: baseURL}.Send(d)
	})
}
