package wop

import (
	"bytes"
	"testing"
)

// A1/A2（spec §5 验收）：黄金向量 conformance 总套件 —— 单一入口消费 fixture
// 每一条向量（正向量字节级一致、负向量全部拒绝），防止任何一条被遗漏。
// 散在各组件的专题测试负责分支细节，本套件负责"全量覆盖"证明。

func TestVectorConformance_Digest(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.Digests) != 2 {
		t.Fatalf("digest 向量条数 = %d, want 2（fixture 完整性哨兵）", len(v.Digests))
	}
	for _, d := range v.Digests {
		suite := mustSuite(t, map[string]string{
			"SHA-256": "WOP-RSA3072-SHA256", "SM3": "WOP-SM2-SM3",
		}[d.Algorithm])
		sum := suite.Digest([]byte(d.Input))
		if LowerHex(sum) != d.ExpectedHex || DigestHeaderValue(suite, []byte(d.Input)) != d.ExpectedHeader {
			t.Errorf("%s 字节级不一致", d.ID)
		}
	}
}

func TestVectorConformance_MessageEncrypt(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.MessageEncrypt) != 2 {
		t.Fatalf("messageEncrypt 条数 = %d, want 2", len(v.MessageEncrypt))
	}
	for _, me := range v.MessageEncrypt {
		suite := mustSuite(t, map[string]string{
			"AES-256-GCM": "WOP-RSA3072-SHA256", "SM4-GCM": "WOP-SM2-SM3",
		}[me.Algorithm])
		ct, err := sealMessage(suite, mustDecodeB64u(t, me.PlaintextB64u),
			mustDecodeB64u(t, me.KeyB64u), mustDecodeB64u(t, me.IvB64u))
		if err != nil || EncodeB64URL(ct) != me.CipherTagB64u {
			t.Errorf("%s 正向量字节级不一致: err=%v", me.ID, err)
		}
		// 负向量：篡改必拒
		bad := append([]byte{}, ct...)
		bad[len(bad)-1] ^= 0x01
		if _, err := openMessage(suite, bad, mustDecodeB64u(t, me.KeyB64u), mustDecodeB64u(t, me.IvB64u)); err == nil {
			t.Errorf("%s tamper 负向量应拒绝", me.ID)
		}
	}
}

func TestVectorConformance_Signature(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.Signature) != 3 {
		t.Fatalf("signature 条数 = %d, want 3", len(v.Signature))
	}
	for _, sv := range v.Signature {
		msg := []byte(sv.Message)
		switch sv.ID {
		case "rsa3072-sign", "rsa4096-sign":
			suiteID := map[string]string{"rsa3072-sign": "WOP-RSA3072-SHA256", "rsa4096-sign": "WOP-RSA4096-SHA256"}[sv.ID]
			suite := mustSuite(t, suiteID)
			key := v.Keys.RSA3072
			if sv.ID == "rsa4096-sign" {
				key = v.Keys.RSA4096
			}
			priv, err := parseRSAPrivateKey(key.PrivatePkcs8B64)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := signMessage(suite, &privKey{rsa: priv}, msg, nil)
			if err != nil {
				t.Fatalf("%s: %v", sv.ID, err)
			}
			if sig != sv.ExpectedSigB64u || len(sig) != sv.B64uLen {
				t.Errorf("%s 签名字节不一致（长度 %d/%d）", sv.ID, len(sig), sv.B64uLen)
			}
			pub, _ := parseRSAPublicKey(key.PublicSpkiB64)
			if err := verifyMessage(suite, &pubKey{rsa: pub}, msg, sig); err != nil {
				t.Errorf("%s 验签失败: %v", sv.ID, err)
			}
		case "sm2-sign-fixedk":
			priv := mustSM2Priv(t, v.Keys.SM2.PrivateDB64)
			k := mustB64uBig(t, v.Inputs.SM2FixedKB64u)
			sig, err := sm2Sign(priv, []byte(v.Inputs.SM2UserID), msg, k, nil)
			if err != nil {
				t.Fatalf("%s: %v", sv.ID, err)
			}
			if got := EncodeB64URL(sig); got != sv.ExpectedSigB64u {
				t.Errorf("%s 签名字节不一致", sv.ID)
			}
			if len(sig) != sv.SigLenBytes {
				t.Errorf("%s 长度 = %d, want %d", sv.ID, len(sig), sv.SigLenBytes)
			}
			// 63/65B 负向量：长度前置拒绝
			pub := mustSM2Pub(t, v.Keys.SM2.PublicPointB64)
			for _, bad := range []string{sv.ExpectedSigB64u[:84], "AA" + sv.ExpectedSigB64u} {
				if err := verifyMessage(mustSuite(t, "WOP-SM2-SM3"), &pubKey{sm2: pub}, msg, bad); err == nil {
					t.Errorf("%s 定长负向量应拒绝", sv.ID)
				}
			}
		default:
			t.Fatalf("未预期签名向量 %q", sv.ID)
		}
	}
}

func TestVectorConformance_KeyEncrypt(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.KeyEncrypt) != 6 {
		t.Fatalf("keyEncrypt 条数 = %d, want 6", len(v.KeyEncrypt))
	}
	privs := map[string]*privKey{}
	_ = privs
	for _, kv := range v.KeyEncrypt {
		switch kv.Expect {
		case "unwrap-equals-plaintext":
			suiteID := "WOP-" + upper(kv.Key) + "-SHA256"
			suite := mustSuite(t, suiteID)
			priv := &privKey{}
			var err error
			if priv.rsa, err = parseRSAPrivateKey(rsaPrivateOf(t, v, kv.Key)); err != nil {
				t.Fatal(err)
			}
			plain, uerr := unwrapDEKPayload(suite, priv, kv.CipherB64u)
			if uerr != nil || string(plain) != kv.ExpectedPlain {
				t.Errorf("%s unwrap 正向量失败: %v", kv.ID, uerr)
			}
		case "reject":
			suite := mustSuite(t, "WOP-RSA3072-SHA256")
			priv := &privKey{}
			var err error
			if priv.rsa, err = parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64); err != nil {
				t.Fatal(err)
			}
			if _, uerr := unwrapDEKPayload(suite, priv, kv.CipherB64u); uerr == nil {
				t.Errorf("%s 负向量应拒绝（%s）", kv.ID, kv.Params)
			}
		case "roundtrip":
			suite := mustSuite(t, "WOP-RSA3072-SHA256")
			pub := &pubKey{}
			priv := &privKey{}
			var err error
			if pub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
				t.Fatal(err)
			}
			if priv.rsa, err = parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64); err != nil {
				t.Fatal(err)
			}
			wrapped, werr := wrapDEKPayload(suite, pub, []byte(kv.Plaintext), nil)
			if werr != nil {
				t.Fatalf("%s wrap: %v", kv.ID, werr)
			}
			plain, uerr := unwrapDEKPayload(suite, priv, wrapped)
			if uerr != nil || !bytes.Equal(plain, []byte(kv.Plaintext)) {
				t.Errorf("%s 往返不一致: %v", kv.ID, uerr)
			}
		case "decrypt-equals-plaintext":
			suite := mustSuite(t, "WOP-SM2-SM3")
			priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
			plain, uerr := unwrapDEKPayload(suite, priv, kv.CipherB64u)
			if uerr != nil || string(plain) != kv.Plaintext {
				t.Errorf("%s 解密正向量失败: %v", kv.ID, uerr)
			}
		default:
			t.Fatalf("未预期 expect %q", kv.Expect)
		}
	}
	// C1C2C3 负向量独立复核
	for _, kv := range v.KeyEncrypt {
		if kv.ID == "sm2-encrypt-c1c2c3-mismatch" {
			suite := mustSuite(t, "WOP-SM2-SM3")
			priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
			if _, uerr := unwrapDEKPayload(suite, priv, kv.CipherB64u); uerr == nil {
				t.Error("C1C2C3 顺序密文应解密失败（D9 顺序钉死）")
			}
		}
	}
}

func TestVectorConformance_DekPayload(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.DekPayload) != 2 {
		t.Fatalf("dekPayload 条数 = %d, want 2", len(v.DekPayload))
	}
	for _, dp := range v.DekPayload {
		got := buildDekPayload(dp.Alg, mustDecodeB64u(t, dp.KeyB64u), mustDecodeB64u(t, dp.IvB64u))
		if got != dp.Expected {
			t.Errorf("%s 组装不一致", dp.ID)
		}
		if _, err := parseDekPayload(got); err != nil {
			t.Errorf("%s 解析失败: %v", dp.ID, err)
		}
	}
}

func TestVectorConformance_FormatRules(t *testing.T) {
	v := loadGoldenVectors(t)
	if len(v.FormatRules) != 8 {
		t.Fatalf("formatRules 条数 = %d, want 8", len(v.FormatRules))
	}
	for _, fr := range v.FormatRules {
		switch {
		case len(fr.ID) > 7 && fr.ID[:7] == "header-":
			// formatRules 钉格式与族耦合（同网关 ContentDigestHeader.validate），不含值比对；
			// 未标 suite 的规则为普适结构负向量
			var err error
			if fr.Suite != "" {
				err = ValidateContentDigestHeader(mustSuite(t, fr.Suite), fr.Value)
			} else {
				_, _, err = ParseContentDigest(fr.Value)
			}
			if fr.Expect == "accept" {
				if err != nil {
					t.Errorf("%s 应接受: %v", fr.ID, err)
				}
			} else if err == nil {
				t.Errorf("%s 应拒绝", fr.ID)
			}
		case len(fr.ID) > 6 && fr.ID[:6] == "b64url":
			if _, err := DecodeB64URL(fr.Value); fr.Expect == "reject" && err == nil {
				t.Errorf("%s 应拒绝", fr.ID)
			}
		default:
			t.Fatalf("未预期 formatRule %q", fr.ID)
		}
	}
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
