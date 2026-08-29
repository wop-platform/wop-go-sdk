package wop

import (
	"crypto/ecdsa"
	"math/big"
	"strings"
	"testing"
)

// spec:F7/D9 白盒补覆盖：sm2raw.go 四条可达缺口（原语层防御分支）。
// 构造依据：sm2E 只读公钥坐标（不含 d），故可先定 k/e 解出 r，
// 再反解 d 使 s = (k − r·d)·(1+d)⁻¹ ≡ 0 (mod n)，精确触发 sm2SignTry 无效分支。

// fixedKInvalidD 由合法私钥派生：保持 PublicKey 不变、替换 D = k·r⁻¹ mod n，
// 使 fixed-k 签名恒产 s=0（GB/T 32918.2 重试条件），触发 sm2Sign 固定 k 拒绝分支。
func fixedKInvalidD(t *testing.T, uid, msg []byte, k *big.Int) (*ecdsa.PrivateKey, func()) {
	t.Helper()
	v := loadGoldenVectors(t)
	priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
	origD := new(big.Int).Set(priv.D)

	n := sm2CurveN()
	e := sm2E(&priv.PublicKey, uid, msg)
	x1, _ := sm2Curve().ScalarBaseMult(pad32(k))
	r := new(big.Int).Add(e, x1)
	r.Mod(r, n)
	if r.Sign() == 0 || new(big.Int).Add(r, k).Cmp(n) == 0 {
		t.Fatal("构造前提失败：r 本身无效，请更换 msg")
	}
	rInv := new(big.Int).ModInverse(r, n)
	if rInv == nil {
		t.Fatal("r 不可逆（n 为素数，理论不可达）")
	}
	d := new(big.Int).Mul(k, rInv)
	d.Mod(d, n)
	onePlusD := new(big.Int).Add(big.NewInt(1), d)
	if new(big.Int).Mod(onePlusD, n).Sign() == 0 || onePlusD.ModInverse(onePlusD, n) == nil {
		t.Fatal("1+d 与 n 不互素（概率 ~2^-256，请更换 msg）")
	}
	priv.D = d
	return priv, func() { priv.D = origD }
}

// 覆盖 sm2raw.go:100（fixed-k 无有效签名）。
func TestSm2Sign_FixedKInvalidSignature(t *testing.T) {
	uid := []byte("1234567812345678")
	msg := []byte("fixed-k s=0 coverage probe")
	priv, restore := fixedKInvalidD(t, uid, msg, big.NewInt(1))
	defer restore()

	_, err := sm2Sign(priv, uid, msg, big.NewInt(1), nil)
	if err == nil || !strings.Contains(err.Error(), "固定 k 无有效签名") {
		t.Fatalf("期望固定 k 无效签名错误，实际 %v", err)
	}
}

// 覆盖 sm2raw.go:121（sm2SignTry r==0 / r+k==n 无效分支）。
func TestSm2SignTry_InvalidR(t *testing.T) {
	n := sm2CurveN()
	k := big.NewInt(1)
	d := big.NewInt(0x2A) // 任意合法标量
	x1, _ := sm2Curve().ScalarBaseMult(pad32(k))

	// r == 0：e ≡ −x1 (mod n)
	e0 := new(big.Int).Neg(x1)
	e0.Mod(e0, n)
	if _, ok := sm2SignTry(e0, d, k, n); ok {
		t.Error("r==0 时 sm2SignTry 应返回 false")
	}

	// r + k == n：e ≡ n−k−x1 (mod n)
	e1 := new(big.Int).Sub(n, k)
	e1.Sub(e1, x1)
	e1.Mod(e1, n)
	if _, ok := sm2SignTry(e1, d, k, n); ok {
		t.Error("r+k==n 时 sm2SignTry 应返回 false")
	}
}

// 覆盖 sm2raw.go:131（sm2SignTry s==0 无效分支）。
func TestSm2SignTry_ZeroS(t *testing.T) {
	n := sm2CurveN()
	k := big.NewInt(1)
	e := big.NewInt(7)
	x1, _ := sm2Curve().ScalarBaseMult(pad32(k))
	r := new(big.Int).Add(e, x1)
	r.Mod(r, n)
	if r.Sign() == 0 || new(big.Int).Add(r, k).Cmp(n) == 0 {
		t.Fatal("构造前提失败：r 无效")
	}
	rInv := new(big.Int).ModInverse(r, n)
	d := new(big.Int).Mul(k, rInv)
	d.Mod(d, n)
	onePlusD := new(big.Int).Add(big.NewInt(1), d)
	if onePlusD.ModInverse(onePlusD, n) == nil {
		t.Fatal("1+d 不可逆")
	}
	if _, ok := sm2SignTry(e, d, k, n); ok {
		t.Error("s==0 时 sm2SignTry 应返回 false")
	}
}

// 覆盖 sm2raw.go:142（sm2Verify 签名长度前置校验）。
func TestSm2Verify_LengthMismatch(t *testing.T) {
	v := loadGoldenVectors(t)
	pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
	uid := []byte(v.Inputs.SM2UserID)
	msg := []byte(v.Inputs.Message)

	for _, bad := range [][]byte{make([]byte, 63), make([]byte, 65), nil} {
		if sm2Verify(pub, uid, msg, bad) {
			t.Errorf("长度 %d 的签名不应通过验签", len(bad))
		}
	}
}
