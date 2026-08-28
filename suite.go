package wop

import "strings"

// Family 是算法体系族（crypto-strategy-spec §2.2）：国际（RSA）与国密（SM2）。
type Family string

const (
	FamilyRSA Family = "RSA"
	FamilySM2 Family = "SM2"
)

// Suite 是一次通信的算法套件上下文（spec §4.4 / §3.2 推导规则），
// 由 securityReq 一次性原子解析（I6），不可变值类型。
type Suite struct {
	securityReq      string
	family           Family
	keyBits          int    // RSA3072/4096；SM2 恒 0
	signAlgorithm    string // ① 签名算法
	messageAlgorithm string // ② 报文加密算法（dek alg 段取值）
	keyWrapAlgorithm string // ③ 密钥包装算法
	digestTag        string // ④ 摘要 header 标签（sha-256 / sm3）
}

// 支持的密钥算法标识（spec §2.2）；映射集中注册于代码，无运行时配置入口（D13）。
var supportedKeyAlgs = map[string]struct{}{
	"RSA3072": {}, "RSA4096": {}, "SM2": {},
}

// 支持的摘要算法标识。
var supportedDigestAlgs = map[string]struct{}{
	"SHA256": {}, "SM3": {},
}

// suiteRegistry 单一注册表：securityReq → 套件（R5/D13，扩展需发版）。
var suiteRegistry = map[string]Suite{
	"WOP-RSA3072-SHA256": {
		securityReq: "WOP-RSA3072-SHA256", family: FamilyRSA, keyBits: 3072,
		signAlgorithm: "SHA256withRSA", messageAlgorithm: "AES-256-GCM",
		keyWrapAlgorithm: "RSA-3072-OAEP", digestTag: "sha-256",
	},
	"WOP-RSA4096-SHA256": {
		securityReq: "WOP-RSA4096-SHA256", family: FamilyRSA, keyBits: 4096,
		signAlgorithm: "SHA256withRSA", messageAlgorithm: "AES-256-GCM",
		keyWrapAlgorithm: "RSA-4096-OAEP", digestTag: "sha-256",
	},
	"WOP-SM2-SM3": {
		securityReq: "WOP-SM2-SM3", family: FamilySM2, keyBits: 0,
		signAlgorithm: "SM3withSM2", messageAlgorithm: "SM4-GCM",
		keyWrapAlgorithm: "SM2", digestTag: "sm3",
	},
}

// ParseSuite 从 securityReq 解析算法套件（F1）。
// 错误分类（spec §2.4）：格式/前缀错误 → 解析类；算法不支持/跨族 → 支持类。
// 两者对外语义均明确。
func ParseSuite(securityReq string) (Suite, error) {
	trimmed := strings.TrimSpace(securityReq)
	if trimmed == "" {
		return Suite{}, newError(CodeSuiteParse, "securityReq 为空")
	}
	parts := strings.Split(trimmed, "-")
	if len(parts) != 3 || parts[0] != "WOP" {
		return Suite{}, newError(CodeSuiteParse,
			"securityReq 格式非法 %q：应为 WOP-<密钥算法>-<摘要算法> 三段式", trimmed)
	}
	keyAlg, digestAlg := parts[1], parts[2]
	if _, ok := supportedKeyAlgs[keyAlg]; !ok {
		return Suite{}, newError(CodeSuiteUnsupported, "不支持的密钥算法 %q（支持 RSA3072/RSA4096/SM2）", keyAlg)
	}
	if _, ok := supportedDigestAlgs[digestAlg]; !ok {
		return Suite{}, newError(CodeSuiteUnsupported, "不支持的摘要算法 %q（支持 SHA256/SM3）", digestAlg)
	}
	suite, ok := suiteRegistry[trimmed]
	if !ok {
		// 注册表覆盖全部合法组合，缺失即跨族（I5：国际/国密互斥贯穿）。
		return Suite{}, newError(CodeSuiteUnsupported,
			"不支持的算法组合 %q：密钥族 %s 与摘要族 %s 跨族", trimmed, keyAlg, digestAlg)
	}
	return suite, nil
}

// SecurityReq 返回原始套件标识串。
func (s Suite) SecurityReq() string { return s.securityReq }

// Family 返回算法体系族（RSA / SM2）。
func (s Suite) Family() Family { return s.family }

// KeyBits 返回 RSA 密钥位数（3072/4096）；SM2 套件恒 0。
func (s Suite) KeyBits() int { return s.keyBits }

// SignAlgorithm 返回推导后的签名算法名（①）。
func (s Suite) SignAlgorithm() string { return s.signAlgorithm }

// MessageAlgorithm 返回 L2 报文对称算法名（②，dek alg 段）。
func (s Suite) MessageAlgorithm() string { return s.messageAlgorithm }

// KeyWrapAlgorithm 返回 DEK 非对称包装算法名（③）。
func (s Suite) KeyWrapAlgorithm() string { return s.keyWrapAlgorithm }

// DigestTag 返回 x-wop-content-digest 算法标签（④，D2）。
func (s Suite) DigestTag() string { return s.digestTag }

// IsSM2 报告是否为国密 SM2 族套件。
func (s Suite) IsSM2() bool { return s.family == FamilySM2 }

// 对称密钥与 IV 长度（spec §3.3 ②：AES-256 key 32B / SM4 key 16B，IV 均 12B）。
func (s Suite) cekLen() int {
	if s.IsSM2() {
		return 16
	}
	return 32
}

// 签名定长（spec §3.3 ①：定长编码使格式校验可前置）：
// RSA = 密钥字节数（3072→384B/512 字符，4096→512B/683 字符）；SM2 = r‖s 64B。
func (s Suite) signatureLen() int {
	if s.IsSM2() {
		return 64
	}
	return s.keyBits / 8
}
