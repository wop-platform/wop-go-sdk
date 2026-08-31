package wop

import (
	"net/http"
	"net/url"
)

// VerifyResult 是 F6 校验管线的结果：OK 为真时 Plaintext 携带 L2 解密后
// 明文（L0 即 wire body）；失败时 Code/Reason 按错误分类总表对外
// （验签/解密类模糊，其余明确，I7）。
type VerifyResult struct {
	OK        bool
	Code      ErrorCode
	Reason    string
	Plaintext []byte
}

// verifyFail 构造失败结果；非 wop.Error 的内部错误按配置类收敛（防御兜底）。
func verifyFail(err error) VerifyResult {
	if we, ok := err.(*Error); ok {
		return VerifyResult{OK: false, Code: we.Code, Reason: we.Message}
	}
	return VerifyResult{OK: false, Code: CodeConfiguration, Reason: "内部错误"}
}

// VerifyResponse 校验网关响应（F6 顺序钉死）：
// 验签 → digest 复核 → DEK 解包 → alg 族比对（解包后、bulk 解密前）→ bulk 解密。
// method/path 为商户原始请求的方法与路径（平台响应 canonical 复用请求 URI）。
func (c *Client) VerifyResponse(method, path string, header http.Header, wireBody []byte) VerifyResult {
	return c.verify(method, path, header, wireBody)
}

// VerifyCallback 校验平台回调（spec §2）：canonical URI 取回调 URL 的 path
// （不含 query），HTTP 方法恒为 POST。
func (c *Client) VerifyCallback(callbackURL string, header http.Header, wireBody []byte) VerifyResult {
	u, err := url.Parse(callbackURL)
	if err != nil || u.Path == "" {
		return verifyFail(newError(CodeParse, "回调 URL 非法：%s", callbackURL))
	}
	return c.verify("POST", u.Path, header, wireBody)
}

// verify F6 管线实现。
func (c *Client) verify(method, path string, header http.Header, wireBody []byte) VerifyResult {
	// 0. 结构化签名头解析
	signRaw := headerValue(header, HeaderSign)
	parsed, err := ParseSignHeader(signRaw)
	if err != nil {
		return verifyFail(err)
	}
	if parsed.securityReq != c.suite.SecurityReq() {
		return verifyFail(newError(CodeParse,
			"响应套件 %q 与客户端配置 %q 不符", parsed.securityReq, c.suite.SecurityReq()))
	}
	suite := c.suite

	// 1. 结构前置校验（公开协议知识，明确拒绝）：D2 有 body 必传 digest、
	//    I1 digest 必入 signedHeaders —— 均不依赖密钥，先于验签。
	hasBody := len(wireBody) > 0
	var digestHeader string
	if hasBody {
		digestHeader = headerValue(header, HeaderContentDigest)
		if digestHeader == "" {
			return verifyFail(newError(CodeIntegrity, "有响应体但缺少 x-wop-content-digest"))
		}
		if !containsHeader(parsed.signedHeaders, HeaderContentDigest) {
			return verifyFail(newError(CodeParse, "x-wop-content-digest 未列入 signedHeaders（I1）"))
		}
	} else if headerValue(header, HeaderContentDigest) != "" {
		return verifyFail(newError(CodeParse, "无响应体不应携带 x-wop-content-digest"))
	}

	// 2. 验签（I2：先验签后解密）：按 signedHeaders 从真实响应头重建 canonical
	signedMap := make(map[string]string, len(parsed.signedHeaders))
	for _, name := range parsed.signedHeaders {
		value := headerValue(header, name)
		if value == "" {
			return verifyFail(newError(CodeParse, "已签名头 %s 在响应中缺失", name))
		}
		signedMap[name] = value
	}
	canonical := CanonicalRequest(parsed.authString(), method, path, "", CanonicalHeaders(signedMap))
	if err := verifyMessage(suite, &c.platformPub, []byte(canonical), parsed.signature); err != nil {
		return verifyFail(err)
	}

	// 3. digest 复核（D2/I5：格式 + 族耦合 + 值比对）
	if hasBody {
		if err := ValidateContentDigest(suite, digestHeader, wireBody); err != nil {
			return verifyFail(err)
		}
	}

	// 4-6. L2：DEK 解包 → alg 族比对 → bulk 解密
	encryptHeader := headerValue(header, HeaderEncrypt)
	if encryptHeader == "" {
		return VerifyResult{OK: true, Plaintext: wireBody}
	}
	_, dekB64u, err := parseEncryptHeader(encryptHeader)
	if err != nil {
		return verifyFail(err)
	}
	payloadPlain, err := unwrapDEKPayload(suite, &c.merchantPriv, dekB64u)
	if err != nil {
		return verifyFail(err) // I7：模糊
	}
	payload, err := parseDekPayload(string(payloadPlain))
	if err != nil {
		// 载荷结构在解包之后才可见，属密钥参与层；除 alg 族不符（D8 明确）外
		// 一律归入解密类模糊（I7 保守默认，与跨仓 interop 合同 n13 对齐）
		return verifyFail(fuzzyError(CodeDecrypt))
	}
	if !payload.matchesSuite(suite) {
		return verifyFail(newError(CodeConsistency,
			"dek alg %q 与套件 %s 族不符（期望 %s）", payload.alg, suite.SecurityReq(), suite.MessageAlgorithm()))
	}
	cipherB64u, err := extractEncryptedBody(wireBody)
	if err != nil {
		return verifyFail(err)
	}
	ciphertext, err := DecodeB64URL(cipherB64u)
	if err != nil {
		return verifyFail(err)
	}
	plaintext, err := openMessage(suite, ciphertext, payload.key, payload.iv)
	if err != nil {
		return verifyFail(err) // I7：模糊
	}
	return VerifyResult{OK: true, Plaintext: plaintext}
}

// containsHeader 判定 target 是否在 signedHeaders 清单中（重放/签名范围核对）。
func containsHeader(names []string, target string) bool {
	for _, n := range names {
		if n == target {
			return true
		}
	}
	return false
}
