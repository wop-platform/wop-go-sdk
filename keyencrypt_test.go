package wop

import (
	"bytes"
	"strings"
	"testing"
)

// F5③：DEK 非对称包装 —— RSA-OAEP 显式双 SHA-256 + 空 label（D10/F2 头号漂移源）。
func TestUnwrapDEK_OAEPVectors(t *testing.T) {
	v := loadGoldenVectors(t)
	for _, keyID := range []string{"rsa3072", "rsa4096"} {
		suiteID := "WOP-" + strings.ToUpper(keyID) + "-SHA256"
		suite := mustSuite(t, suiteID)
		priv := &privKey{}
		var err error
		if priv.rsa, err = parseRSAPrivateKey(rsaPrivateOf(t, v, keyID)); err != nil {
			t.Fatal(err)
		}
		for _, ke := range v.KeyEncrypt {
			if ke.Key != keyID || ke.CipherB64u == "" {
				continue
			}
			switch ke.ID {
			case "oaep3072-unwrap", "oaep4096-unwrap":
				plain, uerr := unwrapDEKPayload(suite, priv, ke.CipherB64u)
				if uerr != nil {
					t.Errorf("%s: %v", ke.ID, uerr)
					continue
				}
				if string(plain) != ke.ExpectedPlain {
					t.Errorf("%s 解包明文 = %q, want %q", ke.ID, plain, ke.ExpectedPlain)
				}
			case "oaep3072-mgf1sha1-trap":
				// F2 钉子：错误 MGF1（SHA-1）包装的密文，用规格参数（双 SHA-256）解包必须失败
				if _, uerr := unwrapDEKPayload(suite, priv, ke.CipherB64u); uerr == nil {
					t.Errorf("%s 应解包失败（MGF1 漂移防护）", ke.ID)
				}
			}
		}
	}
}

func TestWrapUnwrapDEK_Roundtrip(t *testing.T) {
	v := loadGoldenVectors(t)
	payload := []byte(v.Inputs.DekPayloadRSA)

	// RSA：加密随机化无法字节钉，产出密文经规格参数解包须等于明文
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	rsaPub := &pubKey{}
	var err error
	if rsaPub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
		t.Fatal(err)
	}
	rsaPriv := &privKey{}
	if rsaPriv.rsa, err = parseRSAPrivateKey(v.Keys.RSA3072.PrivatePkcs8B64); err != nil {
		t.Fatal(err)
	}
	wrapped, err := wrapDEKPayload(rsaSuite, rsaPub, payload)
	if err != nil {
		t.Fatalf("OAEP 包装: %v", err)
	}
	plain, err := unwrapDEKPayload(rsaSuite, rsaPriv, wrapped)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatalf("OAEP 往返: plain=%q err=%v", plain, err)
	}

	// SM2 往返
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	sm2Pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	sm2Priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
	payloadSm2 := []byte(v.Inputs.DekPayloadSM2)
	wrapped, err = wrapDEKPayload(sm2Suite, sm2Pub, payloadSm2)
	if err != nil {
		t.Fatalf("SM2 包装: %v", err)
	}
	plain, err = unwrapDEKPayload(sm2Suite, sm2Priv, wrapped)
	if err != nil || !bytes.Equal(plain, payloadSm2) {
		t.Fatalf("SM2 往返: plain=%q err=%v", plain, err)
	}

	// 带填充符 b64url 拒绝（协议类）
	if _, err := unwrapDEKPayload(sm2Suite, sm2Priv, "BHg6d-mt="); err == nil {
		t.Error("带 = 的 dek 密文应拒绝")
	} else if err.(*Error).Code != CodeProtocol {
		t.Errorf("错误类 = %s, want CodeProtocol", err.(*Error).Code)
	}
}

// I7：DEK 解包失败对外模糊。
func TestUnwrapDEK_FuzzyOnFailure(t *testing.T) {
	v := loadGoldenVectors(t)
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	sm2Priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
	// 用随机公钥包装 → 私钥不配对 → 解包失败
	other, _ := generateSM2KeyForTest()
	ct, err := sm2Encrypt(&other.PublicKey, []byte(v.Inputs.DekPayloadSM2), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, uerr := unwrapDEKPayload(sm2Suite, sm2Priv, EncodeB64URL(ct))
	if uerr == nil {
		t.Fatal("不配对密钥应解包失败")
	}
	if we := uerr.(*Error); we.Code != CodeDecryptFailed || we.Message != decryptFuzzyMessage {
		t.Errorf("I7 违规：code=%s msg=%q", we.Code, we.Message)
	}
}

// F5②：L2 报文对称加密 —— AES-256-GCM / SM4-GCM，密文 = ciphertext‖tag 尾拼（D10/F4）。
func TestSealMessage_VectorByteLevel(t *testing.T) {
	v := loadGoldenVectors(t)
	for _, me := range v.MessageEncrypt {
		var suite Suite
		switch me.Algorithm {
		case "AES-256-GCM":
			suite = mustSuite(t, "WOP-RSA3072-SHA256")
		case "SM4-GCM":
			suite = mustSuite(t, "WOP-SM2-SM3")
		default:
			t.Fatalf("未知报文算法 %q", me.Algorithm)
		}
		ct, err := sealMessage(suite, mustDecodeB64u(t, me.PlaintextB64u),
			mustDecodeB64u(t, me.KeyB64u), mustDecodeB64u(t, me.IvB64u))
		if err != nil {
			t.Fatalf("%s: %v", me.ID, err)
		}
		if got := EncodeB64URL(ct); got != me.CipherTagB64u {
			t.Errorf("%s 密文字节不一致:\n got %s\nwant %s", me.ID, got, me.CipherTagB64u)
		}
		// tag 128bit（16B）：密文尾部
		if len(ct) != len(mustDecodeB64u(t, me.PlaintextB64u))+16 {
			t.Errorf("%s: 密文长度 %d != 明文 %d + 16B tag", me.ID, len(ct), len(mustDecodeB64u(t, me.PlaintextB64u)))
		}
	}
}

func TestOpenMessage_RoundtripAndTamper(t *testing.T) {
	v := loadGoldenVectors(t)
	for _, me := range v.MessageEncrypt {
		var suite Suite
		if me.Algorithm == "AES-256-GCM" {
			suite = mustSuite(t, "WOP-RSA3072-SHA256")
		} else {
			suite = mustSuite(t, "WOP-SM2-SM3")
		}
		plain := mustDecodeB64u(t, me.PlaintextB64u)
		key := mustDecodeB64u(t, me.KeyB64u)
		iv := mustDecodeB64u(t, me.IvB64u)
		ct := mustDecodeB64u(t, me.CipherTagB64u)

		got, err := openMessage(suite, ct, key, iv)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s 解密: %v", me.ID, err)
		}

		// 篡改密文尾字节（tag）→ 模糊失败
		bad := append([]byte{}, ct...)
		bad[len(bad)-1] ^= 0x01
		_, err = openMessage(suite, bad, key, iv)
		if err == nil {
			t.Errorf("%s 篡改 tag 应失败", me.ID)
		} else if we := err.(*Error); we.Code != CodeDecryptFailed || we.Message != decryptFuzzyMessage {
			t.Errorf("%s I7 违规：code=%s msg=%q", me.ID, we.Code, we.Message)
		}

		// 篡改密文首字节（C2 段）→ 同样模糊失败
		bad = append([]byte{}, ct...)
		bad[0] ^= 0x01
		if _, err = openMessage(suite, bad, key, iv); err == nil {
			t.Errorf("%s 篡改密文头应失败", me.ID)
		}

		// 错误密钥 → 模糊失败
		wrongKey := append([]byte{}, key...)
		wrongKey[0] ^= 0x01
		if _, err = openMessage(suite, ct, wrongKey, iv); err == nil {
			t.Errorf("%s 错误密钥应失败", me.ID)
		}
	}
}

func TestSealMessage_KeyIvLengthChecks(t *testing.T) {
	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	if _, err := sealMessage(rsaSuite, []byte("x"), make([]byte, 16), make([]byte, 12)); err == nil {
		t.Error("AES 密钥 16B 应拒绝（须 32B）")
	}
	if _, err := sealMessage(rsaSuite, []byte("x"), make([]byte, 32), make([]byte, 8)); err == nil {
		t.Error("IV 8B 应拒绝（须 12B）")
	}
	if _, err := sealMessage(sm2Suite, []byte("x"), make([]byte, 32), make([]byte, 12)); err == nil {
		t.Error("SM4 密钥 32B 应拒绝（须 16B）")
	}
}

// F5/§6.1：DEK 载荷 alg$b64u(key)$b64u(iv)，'$' 不在 base64url 字母表，分隔无碰撞。
func TestDekPayload_BuildParseVector(t *testing.T) {
	v := loadGoldenVectors(t)
	for _, dp := range v.DekPayload {
		got := buildDekPayload(dp.Alg, mustDecodeB64u(t, dp.KeyB64u), mustDecodeB64u(t, dp.IvB64u))
		if got != dp.Expected {
			t.Errorf("%s: 载荷 = %q, want %q", dp.ID, got, dp.Expected)
		}
		parsed, err := parseDekPayload(got)
		if err != nil {
			t.Fatalf("%s 解析: %v", dp.ID, err)
		}
		if parsed.alg != dp.Alg || string(parsed.key) != string(mustDecodeB64u(t, dp.KeyB64u)) ||
			string(parsed.iv) != string(mustDecodeB64u(t, dp.IvB64u)) {
			t.Errorf("%s 往返不一致", dp.ID)
		}
	}
}

func TestParseDekPayload_Rejects(t *testing.T) {
	reject := map[string]string{
		"两段":    "AES-256-GCM$AAEC",
		"四段":    "AES-256-GCM$AAEC$EBES$x",
		"未知算法":  "AES-128-GCM$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$EBESExQVFhcYGRob",
		"密钥带=":  "AES-256-GCM$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=$EBESExQVFhcYGRob",
		"密钥长度":  "AES-256-GCM$AAECAwQFBgcICQoLDA0ODxAREhM$EBESExQVFhcYGRob",
		"IV长度":  "AES-256-GCM$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$EBESExQVFhc",
		"SM4键长": "SM4-GCM$AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8$EBESExQVFhcYGRob",
		"空串":    "",
	}
	for name, s := range reject {
		if _, err := parseDekPayload(s); err == nil {
			t.Errorf("%s (%q) 应拒绝", name, s)
		} else if we, ok := err.(*Error); !ok || we.Code != CodeProtocol {
			t.Errorf("%s: 错误类 = %v, want CodeProtocol", name, err)
		}
	}
}

func rsaPrivateOf(t *testing.T, v *goldenVectors, keyID string) string {
	t.Helper()
	if keyID == "rsa4096" {
		return v.Keys.RSA4096.PrivatePkcs8B64
	}
	return v.Keys.RSA3072.PrivatePkcs8B64
}
