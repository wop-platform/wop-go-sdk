package wop

import (
	"crypto/aes"
	"crypto/cipher"
	"strings"

	"github.com/emmansun/gmsm/sm4"
)

// F5②：L2 报文对称加密。AES-256-GCM（key 32B）/ SM4-GCM（key 16B），
// IV 12B，tag 128bit；密文线上格式 = ciphertext‖tag 尾部拼接（D10/F4），
// 整体 base64url 无填充。解密失败对外模糊（I7）。

const gcmIVLen = 12

// sealMessage 以给定 key/iv 加密明文，返回 ciphertext‖tag。
// key/iv 长度与套件不符为配置类明确错误（调用方自查）。
func sealMessage(s Suite, plaintext, key, iv []byte) ([]byte, error) {
	gcm, err := newMessageGCM(s, key)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcmIVLen {
		return nil, newError(CodeConfig, "GCM IV 长度须为 12 字节，实际 %d", len(iv))
	}
	return gcm.Seal(nil, iv, plaintext, nil), nil
}

// openMessage 解密 ciphertext‖tag；任何失败（tag 不符、密钥不符）对外模糊（I7）。
func openMessage(s Suite, ciphertext, key, iv []byte) ([]byte, error) {
	gcm, err := newMessageGCM(s, key)
	if err != nil {
		return nil, err
	}
	if len(iv) != gcmIVLen {
		return nil, newError(CodeConfig, "GCM IV 长度须为 12 字节，实际 %d", len(iv))
	}
	plain, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fuzzyError(CodeDecryptFailed)
	}
	return plain, nil
}

func newMessageGCM(s Suite, key []byte) (cipher.AEAD, error) {
	want := s.cekLen()
	if len(key) != want {
		return nil, newError(CodeConfig, "报文密钥长度须为 %d 字节，实际 %d", want, len(key))
	}
	var block cipher.Block
	var err error
	if s.IsSM2() {
		block, err = sm4.NewCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, newError(CodeConfig, "报文对称密钥非法：%v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newError(CodeConfig, "GCM 初始化失败：%v", err)
	}
	return gcm, nil
}

// dekPayload 是 DEK 载荷（spec §6.1）：alg$b64url(key)$b64url(iv)。
type dekPayload struct {
	alg string
	key []byte
	iv  []byte
}

// buildDekPayload 组装线上载荷串。
func buildDekPayload(alg string, key, iv []byte) string {
	return alg + "$" + EncodeB64URL(key) + "$" + EncodeB64URL(iv)
}

// 支持的报文对称算法 → 密钥长度（公开协议知识，D13 注册表）。
var messageAlgKeyLens = map[string]int{
	"AES-256-GCM": 32,
	"SM4-GCM":     16,
}

// parseDekPayload 严格解析载荷：恰三段、算法已知、key/iv 长度匹配、b64url 严格。
// 结构非法为协议类明确错误（解析时序：解包之后、bulk 解密之前，D8）。
func parseDekPayload(payload string) (dekPayload, error) {
	parts := strings.Split(payload, "$")
	if len(parts) != 3 {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷须为 alg$key$iv 三段，实际 %d 段", len(parts))
	}
	keyLen, ok := messageAlgKeyLens[parts[0]]
	if !ok {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷 alg %q 不在支持列表（AES-256-GCM/SM4-GCM）", parts[0])
	}
	key, err := DecodeB64URL(parts[1])
	if err != nil {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷 key 段解码失败")
	}
	iv, err := DecodeB64URL(parts[2])
	if err != nil {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷 iv 段解码失败")
	}
	if len(key) != keyLen {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷 alg %s 密钥须 %d 字节，实际 %d", parts[0], keyLen, len(key))
	}
	if len(iv) != gcmIVLen {
		return dekPayload{}, newError(CodeProtocol, "DEK 载荷 iv 须 12 字节，实际 %d", len(iv))
	}
	return dekPayload{alg: parts[0], key: key, iv: iv}, nil
}

// matchesSuite 校验载荷 alg 与套件族一致（I3/I5：AES-256-GCM↔RSA、SM4-GCM↔SM2）。
func (d dekPayload) matchesSuite(s Suite) bool {
	return d.alg == s.MessageAlgorithm()
}
