package wop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

// SM2 原始协议数学（GB/T 32918，D9 三钉：签名裸 r‖s 64B、密文 C1C3C2
// 裸拼接、线上禁 ASN.1/DER）。椭圆曲线运算与 SM3 由 emmansun/gmsm 提供，
// 协议编排在本层钉死，k 注入点显式化（黄金向量 fixed-k 的唯一入口）。

// sm2Curve SM2 推荐曲线 sm2p256v1。
func sm2Curve() ellipticCurve { return sm2.P256() }

// ellipticCurve 别名收敛 deprecated 接口的使用面（仅本文件消费）。
type ellipticCurve = interface {
	IsOnCurve(x, y *big.Int) bool
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
}

// pad32 大端定长 32 字节（I2OSP）。
func pad32(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

func sm2CurveN() *big.Int { return sm2.P256().Params().N }

// a = p − 3（sm2p256v1 曲线参数）。
func sm2ZA(pub *ecdsa.PublicKey, uid []byte) []byte {
	params := sm2.P256().Params()
	a := new(big.Int).Sub(params.P, big.NewInt(3))
	entla := uint16(len(uid) * 8)

	h := sm3.New()
	var entlaBytes [2]byte
	entlaBytes[0] = byte(entla >> 8)
	entlaBytes[1] = byte(entla)
	h.Write(entlaBytes[:])
	h.Write(uid)
	h.Write(pad32(a))
	h.Write(pad32(params.B))
	h.Write(pad32(params.Gx))
	h.Write(pad32(params.Gy))
	h.Write(pad32(pub.X))
	h.Write(pad32(pub.Y))
	return h.Sum(nil)
}

// sm2E 计算 e = SM3(ZA‖M) 的整数值。
func sm2E(pub *ecdsa.PublicKey, uid, msg []byte) *big.Int {
	h := sm3.New()
	h.Write(sm2ZA(pub, uid))
	h.Write(msg)
	return new(big.Int).SetBytes(h.Sum(nil))
}

// randomScalar 生成 [1, n-1] 随机标量（CSPRNG；I4 纪律：每次调用独立随机）。
func randomScalar() (*big.Int, error) {
	n := sm2CurveN()
	one := big.NewInt(1)
	for {
		k, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			_ = one
			return k, nil
		}
	}
}

// sm2Sign 以私钥对 msg 签名，输出裸 r‖s 各 32B 大端（D9，线上禁 DER）。
// k 为 nil 时由 CSPRNG 生成；非 nil 时仅限测试向量消费（fixed-k 锚点）。
func sm2Sign(priv *ecdsa.PrivateKey, uid, msg []byte, k *big.Int) ([]byte, error) {
	n := sm2CurveN()
	e := sm2E(&priv.PublicKey, uid, msg)
	d := priv.D

	for attempt := 0; attempt < 8; attempt++ {
		var ki *big.Int
		if k != nil {
			if attempt > 0 {
				return nil, errors.New("sm2: 固定 k 无有效签名（测试向量非法）")
			}
			ki = k
		} else {
			var err error
			ki, err = randomScalar()
			if err != nil {
				return nil, err
			}
		}
		x1, _ := sm2Curve().ScalarBaseMult(pad32(ki))
		r := new(big.Int).Add(e, x1)
		r.Mod(r, n)
		if r.Sign() == 0 {
			continue
		}
		rk := new(big.Int).Add(r, ki)
		if rk.Cmp(n) == 0 {
			continue
		}
		// s = (1+d)^-1 · (k − r·d) mod n
		oneMinusDInv := new(big.Int).Add(big.NewInt(1), d)
		oneMinusDInv.ModInverse(oneMinusDInv, n)
		rd := new(big.Int).Mul(r, d)
		s := new(big.Int).Sub(ki, rd)
		s.Mul(s, oneMinusDInv)
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil
	}
	return nil, errors.New("sm2: 多次重试后仍未获得有效签名")
}

// sm2Verify 验证裸 r‖s 64B 签名（GB/T 32918.2 验签等式）。
func sm2Verify(pub *ecdsa.PublicKey, uid, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	n := sm2CurveN()
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, n)
	if t.Sign() == 0 {
		return false
	}
	e := sm2E(pub, uid, msg)
	// (x1, y1) = s·G + t·PA
	sgx, sgy := sm2Curve().ScalarBaseMult(pad32(s))
	tpx, tpy := sm2Curve().ScalarMult(pub.X, pub.Y, pad32(t))
	x1, _ := sm2Curve().Add(sgx, sgy, tpx, tpy)
	if x1 == nil {
		return false
	}
	rCheck := new(big.Int).Add(e, x1)
	rCheck.Mod(rCheck, n)
	return rCheck.Cmp(r) == 0
}

// sm2KDF 密钥派生函数（GB/T 32918.4）：W = W ‖ SM3(Z ‖ ct)，ct 为 32 位大端计数器。
func sm2KDF(z []byte, klen int) []byte {
	var out []byte
	ct := uint32(1)
	for len(out) < klen {
		h := sm3.New()
		h.Write(z)
		var ctBytes [4]byte
		ctBytes[0] = byte(ct >> 24)
		ctBytes[1] = byte(ct >> 16)
		ctBytes[2] = byte(ct >> 8)
		ctBytes[3] = byte(ct)
		h.Write(ctBytes[:])
		out = append(out, h.Sum(nil)...)
		ct++
	}
	return out[:klen]
}

// sm2Encrypt 公钥加密，输出 C1C3C2 裸拼接（新国标，D9）：
// C1 = 未压缩点 65B，C3 = SM3(x2‖M‖y2) 32B，C2 = M ⊕ KDF(x2‖y2)。
// k 为 nil 时 CSPRNG 生成；非 nil 仅限测试向量消费。
func sm2Encrypt(pub *ecdsa.PublicKey, msg []byte, k *big.Int) ([]byte, error) {
	for attempt := 0; attempt < 8; attempt++ {
		var ki *big.Int
		if k != nil {
			if attempt > 0 {
				return nil, errors.New("sm2: 固定 k 无有效密文（测试向量非法）")
			}
			ki = k
		} else {
			var err error
			ki, err = randomScalar()
			if err != nil {
				return nil, err
			}
		}
		c1x, c1y := sm2Curve().ScalarBaseMult(pad32(ki))
		x2, y2 := sm2Curve().ScalarMult(pub.X, pub.Y, pad32(ki))
		z := concat32(x2, y2)
		t := sm2KDF(z, len(msg))
		// KDF 输出全零 → 重换 k（GB/T 32918.4 要求）
		allZero := true
		for _, b := range t {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero && len(msg) > 0 {
			continue
		}
		c2 := make([]byte, len(msg))
		for i := range msg {
			c2[i] = msg[i] ^ t[i]
		}
		h := sm3.New()
		h.Write(pad32(x2))
		h.Write(msg)
		h.Write(pad32(y2))
		c3 := h.Sum(nil)

		out := make([]byte, 0, 65+32+len(msg))
		out = append(out, 0x04)
		out = append(out, pad32(c1x)...)
		out = append(out, pad32(c1y)...)
		out = append(out, c3...)
		out = append(out, c2...)
		return out, nil
	}
	return nil, errors.New("sm2: 多次重试后仍未获得有效密文")
}

// sm2Decrypt 私钥解密 C1C3C2 裸拼接密文；任何失败（点非法、KDF 全零、
// C3 校验不符、长度不足）统一报错，错误细节不外泄（I7 由上层收敛）。
func sm2Decrypt(priv *ecdsa.PrivateKey, cipher []byte) ([]byte, error) {
	if len(cipher) < 65+32 {
		return nil, errors.New("sm2: 密文过短")
	}
	if cipher[0] != 0x04 {
		return nil, errors.New("sm2: C1 须为未压缩点")
	}
	c1x := new(big.Int).SetBytes(cipher[1:33])
	c1y := new(big.Int).SetBytes(cipher[33:65])
	if !sm2Curve().IsOnCurve(c1x, c1y) {
		return nil, errors.New("sm2: C1 不在曲线上")
	}
	c3 := cipher[65:97]
	c2 := cipher[97:]

	x2, y2 := sm2Curve().ScalarMult(c1x, c1y, pad32(priv.D))
	z := concat32(x2, y2)
	t := sm2KDF(z, len(c2))
	allZero := true
	for _, b := range t {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero && len(c2) > 0 {
		return nil, errors.New("sm2: KDF 输出全零")
	}
	msg := make([]byte, len(c2))
	for i := range c2 {
		msg[i] = c2[i] ^ t[i]
	}
	h := sm3.New()
	h.Write(pad32(x2))
	h.Write(msg)
	h.Write(pad32(y2))
	if !equalBytes(h.Sum(nil), c3) {
		return nil, errors.New("sm2: C3 校验失败")
	}
	return msg, nil
}

func concat32(x, y *big.Int) []byte {
	z := make([]byte, 0, 64)
	z = append(z, pad32(x)...)
	z = append(z, pad32(y)...)
	return z
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// sm2PrivateKeyFromScalar 从标量构造 SM2 私钥（派生公钥 = d·G）。
func sm2PrivateKeyFromScalar(d *big.Int) (*ecdsa.PrivateKey, error) {
	raw := pad32(d)
	priv, err := sm2.NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return &priv.PrivateKey, nil
}
