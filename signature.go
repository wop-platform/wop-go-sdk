package wop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// F3/F7：结构化签名层。签名对象 = canonicalRequest UTF-8 字节；
// RSA 族 = SHA256withRSA（PKCS#1 v1.5，确定性）；SM2 族 = SM3withSM2
// 裸 r‖s 64B（D9）。线上编码 base64url 无填充。

// sm2DefaultUserID SM2 签名默认用户标识（协议向量钉死）。
var sm2DefaultUserID = []byte("1234567812345678")

// signKey 商户侧签名密钥（按套件族二选一填充）。
type signKey struct {
	rsa *rsa.PrivateKey
	sm2 *ecdsa.PrivateKey
}

// verifyKey 验签方公钥（按套件族二选一填充）。
type verifyKey struct {
	rsa *rsa.PublicKey
	sm2 *ecdsa.PublicKey
}

// signMessage 对 msg 加签，返回 base64url 无填充签名。
func signMessage(s Suite, key *signKey, msg []byte) (string, error) {
	switch {
	case s.IsSM2():
		if key.sm2 == nil {
			return "", newError(CodeConfig, "SM2 套件缺少私钥")
		}
		sig, err := sm2Sign(key.sm2, sm2DefaultUserID, msg, nil)
		if err != nil {
			return "", fuzzyError(CodeVerifyFailed) // 加签失败对外模糊（密钥参与）
		}
		return EncodeB64URL(sig), nil
	default:
		if key.rsa == nil {
			return "", newError(CodeConfig, "RSA 套件缺少私钥")
		}
		digest := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.rsa, cryptoSHA256, digest[:])
		if err != nil {
			return "", fuzzyError(CodeVerifyFailed)
		}
		return EncodeB64URL(sig), nil
	}
}

// verifyMessage 验签：b64url 严格解码 → 定长前置校验（F7）→ 族路由验签。
// 失败一律模糊（I7：CodeVerifyFailed + 固定文案）；格式/长度类为协议明确错误。
func verifyMessage(s Suite, key *verifyKey, msg []byte, sigB64u string) error {
	sig, err := DecodeB64URL(sigB64u)
	if err != nil {
		return err
	}
	if len(sig) != s.signatureLen() {
		return newError(CodeProtocol, "签名长度 %d 字节与套件 %s 定长 %d 字节不符",
			len(sig), s.SecurityReq(), s.signatureLen())
	}
	switch {
	case s.IsSM2():
		if key.sm2 == nil {
			return newError(CodeConfig, "SM2 套件缺少验签公钥")
		}
		if !sm2Verify(key.sm2, sm2DefaultUserID, msg, sig) {
			return fuzzyError(CodeVerifyFailed)
		}
		return nil
	default:
		if key.rsa == nil {
			return newError(CodeConfig, "RSA 套件缺少验签公钥")
		}
		digest := sha256.Sum256(msg)
		if err := rsa.VerifyPKCS1v15(key.rsa, cryptoSHA256, digest[:], sig); err != nil {
			return fuzzyError(CodeVerifyFailed)
		}
		return nil
	}
}

// cryptoSHA256 签名/验签摘要算法标识。
const cryptoSHA256 = crypto.SHA256
