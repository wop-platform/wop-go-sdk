package wop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"
	"testing"
)

// D9 三钉：签名裸 r‖s 64B、密文 C1C3C2 裸拼接、线上禁 ASN.1。
// 全部以黄金向量字节级断言（fixture sm2-sign-fixedk / sm2-encrypt-fixedk）。
func TestSM2Sign_FixedK_Vector(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	msg := []byte(v.Inputs.Message)
	k := mustB64uBig(t, v.Inputs.SM2FixedKB64u)

	sig, err := sm2Sign(priv, []byte(v.Inputs.SM2UserID), msg, k, nil)
	if err != nil {
		t.Fatalf("sm2Sign: %v", err)
	}
	if got := EncodeB64URL(sig); got != mustFirstSig(t, v, "sm2-sign-fixedk") {
		t.Fatalf("fixed-k 签名字节不一致:\n got %s\nwant %s", got, mustFirstSig(t, v, "sm2-sign-fixedk"))
	}
	if len(sig) != 64 {
		t.Fatalf("签名长度 = %d, want 64", len(sig))
	}
}

func TestSM2Verify_VectorAndNegatives(t *testing.T) {
	v := loadGoldenVectors(t)
	pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
	msg := []byte(v.Inputs.Message)
	sig := mustDecodeB64u(t, mustFirstSig(t, v, "sm2-sign-fixedk"))

	if !sm2Verify(pub, []byte(v.Inputs.SM2UserID), msg, sig) {
		t.Fatal("向量签名应验签通过")
	}
	if sm2Verify(pub, []byte(v.Inputs.SM2UserID), []byte("tampered"), sig) {
		t.Fatal("篡改消息后不应通过")
	}
	// r 翻转一位 → 失败
	bad := append([]byte{}, sig...)
	bad[10] ^= 0x01
	if sm2Verify(pub, []byte(v.Inputs.SM2UserID), msg, bad) {
		t.Fatal("篡改 r 后不应通过")
	}
	// 错误 userId（ZA 不同）→ 失败
	if sm2Verify(pub, []byte("other-user-id-000000000"), msg, sig) {
		t.Fatal("错误 userId 不应通过")
	}
	// r=0 / s=0 → 非法
	zero := append([]byte{}, sig...)
	copy(zero[:32], make([]byte, 32))
	if sm2Verify(pub, []byte(v.Inputs.SM2UserID), msg, zero) {
		t.Fatal("r=0 不应通过")
	}
	zero = append([]byte{}, sig...)
	copy(zero[32:], make([]byte, 32))
	if sm2Verify(pub, []byte(v.Inputs.SM2UserID), msg, zero) {
		t.Fatal("s=0 不应通过")
	}
	// r+s ≡ 0 构造：s = n - r（若 s 合法则 t=0 → 拒）
	n := sm2CurveN()
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).Sub(n, r)
	if s.Sign() > 0 && s.Cmp(n) < 0 {
		zeroTSig := make([]byte, 64)
		copy(zeroTSig[:32], sig[:32])
		s.FillBytes(zeroTSig[32:])
		if sm2Verify(pub, []byte(v.Inputs.SM2UserID), msg, zeroTSig) {
			t.Fatal("t=r+s≡0 不应通过")
		}
	}
}

func TestSM2Sign_RandomK_Roundtrip(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	msg := []byte("随机 k 签名往返")
	sig, err := sm2Sign(priv, []byte(v.Inputs.SM2UserID), msg, nil, nil)
	if err != nil {
		t.Fatalf("sm2Sign random: %v", err)
	}
	if !sm2Verify(&priv.PublicKey, []byte(v.Inputs.SM2UserID), msg, sig) {
		t.Fatal("随机 k 签名应可通过验签")
	}
	// 两次签名不同（k 随机）
	sig2, _ := sm2Sign(priv, []byte(v.Inputs.SM2UserID), msg, nil, nil)
	if bytes.Equal(sig, sig2) {
		t.Fatal("随机 k 两次签名不应相同（碰撞概率可忽略）")
	}
}

func TestSM2Encrypt_FixedK_Vector(t *testing.T) {
	v := loadGoldenVectors(t)
	pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
	k := mustB64uBig(t, v.Inputs.SM2FixedKB64u)

	var want string
	for _, ke := range v.KeyEncrypt {
		if ke.ID == "sm2-encrypt-fixedk" {
			want = ke.CipherB64u
		}
	}
	ct, err := sm2Encrypt(pub, []byte(v.Inputs.DekPayloadSM2), k, nil)
	if err != nil {
		t.Fatalf("sm2Encrypt: %v", err)
	}
	if got := EncodeB64URL(ct); got != want {
		t.Fatalf("fixed-k 密文字节不一致:\n got %s\nwant %s", got, want)
	}
}

func TestSM2Decrypt_VectorAndNegatives(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)

	var good, c1c2c3 string
	for _, ke := range v.KeyEncrypt {
		switch ke.ID {
		case "sm2-encrypt-fixedk":
			good = ke.CipherB64u
		case "sm2-encrypt-c1c2c3-mismatch":
			c1c2c3 = ke.CipherB64u
		}
	}
	plain, err := sm2Decrypt(priv, mustDecodeB64u(t, good))
	if err != nil {
		t.Fatalf("向量密文解密失败: %v", err)
	}
	if string(plain) != v.Inputs.DekPayloadSM2 {
		t.Fatalf("解密明文 = %q, want %q", plain, v.Inputs.DekPayloadSM2)
	}

	// 旧国标 C1C2C3 顺序密文按 C1C3C2 解密必须失败（D9 顺序钉死）
	if _, err := sm2Decrypt(priv, mustDecodeB64u(t, c1c2c3)); err == nil {
		t.Fatal("C1C2C3 顺序密文应解密失败")
	}

	// 篡改 C3（65..97 字节段）
	tampered := append([]byte{}, mustDecodeB64u(t, good)...)
	tampered[70] ^= 0x01
	if _, err := sm2Decrypt(priv, tampered); err == nil {
		t.Fatal("篡改 C3 应解密失败")
	}
	// 篡改 C2
	tampered[100] ^= 0x01
	if _, err := sm2Decrypt(priv, tampered); err == nil {
		t.Fatal("篡改 C2 应解密失败")
	}
	// 长度不足（< 65+32）
	if _, err := sm2Decrypt(priv, make([]byte, 90)); err == nil {
		t.Fatal("过短密文应失败")
	}
	// C1 不在曲线上（首字节改 0x04 保留、坐标改零）
	badC1 := append([]byte{}, mustDecodeB64u(t, good)...)
	copy(badC1[1:33], make([]byte, 32))
	if _, err := sm2Decrypt(priv, badC1); err == nil {
		t.Fatal("C1 不在曲线上应失败")
	}
}

func TestSM2EncryptDecrypt_RandomK_Roundtrip(t *testing.T) {
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	msg := []byte("round-trip 消息 with ASCII & 中文")
	ct, err := sm2Encrypt(&priv.PublicKey, msg, nil, nil)
	if err != nil {
		t.Fatalf("sm2Encrypt random: %v", err)
	}
	plain, err := sm2Decrypt(priv, ct)
	if err != nil {
		t.Fatalf("sm2Decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("往返明文不一致")
	}
	// 空消息
	ct, err = sm2Encrypt(&priv.PublicKey, nil, nil, nil)
	if err != nil {
		t.Fatalf("空消息加密: %v", err)
	}
	if plain, err = sm2Decrypt(priv, ct); err != nil || len(plain) != 0 {
		t.Fatalf("空消息解密: plain=%q err=%v", plain, err)
	}
}

func mustSM2Priv(t *testing.T, b64 string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := parseSM2PrivateKey(b64)
	if err != nil {
		t.Fatalf("parseSM2PrivateKey: %v", err)
	}
	return priv
}

func mustSM2Pub(t *testing.T, b64 string) *ecdsa.PublicKey {
	t.Helper()
	pub, err := parseSM2PublicKey(b64)
	if err != nil {
		t.Fatalf("parseSM2PublicKey: %v", err)
	}
	return pub
}

func mustDecodeB64u(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := DecodeB64URL(s)
	if err != nil {
		t.Fatalf("DecodeB64URL(%s): %v", s, err)
	}
	return raw
}

func mustB64uBig(t *testing.T, s string) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(mustDecodeB64u(t, s))
}

func mustFirstSig(t *testing.T, v *goldenVectors, id string) string {
	t.Helper()
	for _, sig := range v.Signature {
		if sig.ID == id {
			return sig.ExpectedSigB64u
		}
	}
	t.Fatalf("向量 %s 不存在", id)
	return ""
}

var _ = rand.Int // 保持导入（构造测试用）
