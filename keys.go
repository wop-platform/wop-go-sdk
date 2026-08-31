package wop

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"

	"github.com/emmansun/gmsm/sm2"
)

// 密钥分发契约（D12）：密钥入参为字符串（PEM 或 Base64 单行），SDK 内部解析。
// RSA 公钥 = X.509 SPKI DER、私钥 = PKCS#8；SM2 公钥 = 未压缩点 04‖X‖Y（65B）、
// 私钥 = d 32B 大端标量。解析失败 → 配置类明确错误（帮助商户自查）。

// decodeKeyMaterial 归一密钥材料：PEM 块取其 DER 体；否则按标准 Base64
// 解码（容忍换行折行）。
func decodeKeyMaterial(material string) ([]byte, error) {
	trimmed := strings.TrimSpace(material)
	if trimmed == "" {
		return nil, newError(CodeConfig, "密钥材料为空")
	}
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		return block.Bytes, nil
	}
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, trimmed)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, newError(CodeConfig, "密钥 Base64 解码失败：%v", err)
	}
	return der, nil
}

// parseRSAPublicKey 解析 RSA 公钥（X.509 SPKI，PEM 或 Base64，D12）。
func parseRSAPublicKey(material string) (*rsa.PublicKey, error) {
	der, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, newError(CodeConfig, "RSA 公钥解析失败（须 X.509 SPKI，PEM 或 Base64）：%v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, newError(CodeConfig, "密钥不是 RSA 公钥（实际 %T）", pub)
	}
	return rsaPub, nil
}

// parseRSAPrivateKey 解析 RSA 私钥（PKCS#8，PEM 或 Base64，D12）。
func parseRSAPrivateKey(material string) (*rsa.PrivateKey, error) {
	der, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, newError(CodeConfig, "RSA 私钥解析失败（须 PKCS#8，PEM 或 Base64）：%v", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, newError(CodeConfig, "密钥不是 RSA 私钥（实际 %T）", key)
	}
	return rsaKey, nil
}

// parseSM2PublicKey 解析 65B 未压缩点（04‖X‖Y，D12）。
func parseSM2PublicKey(material string) (*ecdsa.PublicKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, newError(CodeConfig, "SM2 公钥须为未压缩点 04‖X‖Y 共 65 字节（Base64），实际 %d 字节", len(raw))
	}
	pub, err := sm2.NewPublicKey(raw)
	if err != nil {
		return nil, newError(CodeConfig, "SM2 公钥点非法（不在 sm2p256v1 曲线上）：%v", err)
	}
	return pub, nil
}

// parseSM2PrivateKey 解析 32B 大端标量 d（D12），范围 [1, n-1]。
func parseSM2PrivateKey(material string) (*ecdsa.PrivateKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, newError(CodeConfig, "SM2 私钥须为 32 字节大端标量 d（Base64），实际 %d 字节", len(raw))
	}
	d := new(big.Int).SetBytes(raw)
	n := sm2.P256().Params().N
	if d.Sign() == 0 || d.Cmp(n) >= 0 {
		return nil, newError(CodeConfig, "SM2 私钥标量 d 超出 [1, n-1] 范围")
	}
	return sm2PrivateKeyFromScalar(d)
}

// validateRSAKeySize 校验密钥位数与套件声明一致（WOP-RSA3072-* → 3072 位）。
func validateRSAKeySize(s Suite, key *rsa.PrivateKey) error {
	return validateRSASize(s, key.N.BitLen())
}

// validateRSASize 校验密钥位数与套件 keyBits 一致（供公私钥两路复用）。
func validateRSASize(s Suite, bits int) error {
	if bits != s.KeyBits() {
		return newError(CodeConfig, "RSA 密钥位数 %d 与套件 %s 要求的 %d 位不符",
			bits, s.SecurityReq(), s.KeyBits())
	}
	return nil
}
