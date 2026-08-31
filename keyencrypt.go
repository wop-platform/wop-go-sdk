package wop

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"strings"
)

// F5③：DEK 非对称包装。
// RSA 族 = RSA-OAEP 显式双 SHA-256 + 空 label（Go 单哈希模型天然满足：
// EncryptOAEP 的 MGF1 摘要与主摘要同为 SHA-256，label=nil 即空）；
// SM2 族 = SM2 公钥加密，C1C3C2 裸拼接（D9）。
// 解包失败对外一律模糊（I7：CodeDecrypt 固定文案）。

// wrapDEKPayload 用公钥包装 DEK 载荷明文，返回 base64url 无填充密文。
func wrapDEKPayload(s Suite, pub *pubKey, payload []byte, random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	switch {
	case s.IsSM2():
		if pub.sm2 == nil {
			return "", newError(CodeConfiguration, "SM2 套件缺少 DEK 包装公钥")
		}
		ct, err := sm2Encrypt(pub.sm2, payload, nil, random)
		if err != nil {
			return "", fuzzyError(CodeDecrypt)
		}
		return EncodeB64URL(ct), nil
	default:
		if pub.rsa == nil {
			return "", newError(CodeConfiguration, "RSA 套件缺少 DEK 包装公钥")
		}
		ct, err := rsa.EncryptOAEP(sha256.New(), random, pub.rsa, payload, nil)
		if err != nil {
			return "", fuzzyError(CodeDecrypt)
		}
		return EncodeB64URL(ct), nil
	}
}

// unwrapDEKPayload 用私钥解包 DEK 密文（base64url）。
// b64url 非法为协议类明确错误；解包失败为解密类模糊错误（I7）。
func unwrapDEKPayload(s Suite, priv *privKey, dekB64u string) ([]byte, error) {
	ct, err := DecodeB64URL(strings.TrimSpace(dekB64u))
	if err != nil {
		return nil, err
	}
	switch {
	case s.IsSM2():
		if priv.sm2 == nil {
			return nil, newError(CodeConfiguration, "SM2 套件缺少 DEK 解包私钥")
		}
		plain, err := sm2Decrypt(priv.sm2, ct)
		if err != nil {
			return nil, fuzzyError(CodeDecrypt)
		}
		return plain, nil
	default:
		if priv.rsa == nil {
			return nil, newError(CodeConfiguration, "RSA 套件缺少 DEK 解包私钥")
		}
		plain, err := rsa.DecryptOAEP(sha256.New(), nil, priv.rsa, ct, nil)
		if err != nil {
			return nil, fuzzyError(CodeDecrypt)
		}
		return plain, nil
	}
}
