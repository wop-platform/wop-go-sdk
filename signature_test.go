package wop

import (
	"crypto/ecdsa"
	"testing"
)

// F3/F7：结构化签名 —— 套件路由 RSA(PKCS#1 v1.5+SHA-256) / SM2(SM3withSM2 裸 r‖s)。
// PKCS#1 v1.5 确定性 → RSA 向量必须字节级一致。
func TestSignMessage_RSAVectors_ByteLevel(t *testing.T) {
	v := loadGoldenVectors(t)
	msg := []byte(v.Inputs.Message)

	for _, tc := range []struct {
		suiteID, privKey, wantSig string
		wantB64uLen               int
	}{
		{"WOP-RSA3072-SHA256", v.Keys.RSA3072.PrivatePkcs8B64, "", 512},
		{"WOP-RSA4096-SHA256", v.Keys.RSA4096.PrivatePkcs8B64, "", 683},
	} {
		suite := mustSuite(t, tc.suiteID)
		for _, sig := range v.Signature {
			if (tc.suiteID == "WOP-RSA3072-SHA256" && sig.ID == "rsa3072-sign") ||
				(tc.suiteID == "WOP-RSA4096-SHA256" && sig.ID == "rsa4096-sign") {
				tc.wantSig = sig.ExpectedSigB64u
			}
		}
		priv := &privKey{}
		var err error
		if priv.rsa, err = parseRSAPrivateKey(tc.privKey); err != nil {
			t.Fatalf("%s 私钥: %v", tc.suiteID, err)
		}
		sig, err := signMessage(suite, priv, nil, msg, nil)
		if err != nil {
			t.Fatalf("%s 签名: %v", tc.suiteID, err)
		}
		if sig != tc.wantSig {
			t.Errorf("%s 签名字节不一致:\n got %s\nwant %s", tc.suiteID, sig, tc.wantSig)
		}
		if len(sig) != tc.wantB64uLen {
			t.Errorf("%s b64u 长度 = %d, want %d", tc.suiteID, len(sig), tc.wantB64uLen)
		}

		pub := &pubKey{}
		if pub.rsa, err = parseRSAPublicKey(publicOf(t, v, tc.suiteID)); err != nil {
			t.Fatalf("%s 公钥: %v", tc.suiteID, err)
		}
		if err := verifyMessage(suite, pub, msg, sig); err != nil {
			t.Errorf("%s 自验签失败: %v", tc.suiteID, err)
		}
	}
}

func TestSignVerifyMessage_SM2Roundtrip(t *testing.T) {
	v := loadGoldenVectors(t)
	suite := mustSuite(t, "WOP-SM2-SM3")
	priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
	pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	msg := []byte("canonical\nPOST\n/p\n\nx-wop-nonce:n1")

	sig, err := signMessage(suite, priv, sm2PlatformUserID, msg, nil)
	if err != nil {
		t.Fatalf("SM2 签名: %v", err)
	}
	if len(sig) != 86 {
		t.Errorf("SM2 b64u 长度 = %d, want 86（64B 裸 r||s）", len(sig))
	}
	if err := verifyMessage(suite, pub, msg, sig); err != nil {
		t.Fatalf("SM2 验签: %v", err)
	}
	if err := verifyMessage(suite, pub, []byte("other"), sig); err == nil {
		t.Error("篡改消息应验签失败")
	}
}

// spec:D14-1 出向签名 userId 同源：固定 appKey 签出的 SM2 签名只能以
// 同一 userId（= appKey 头值）验签通过；平台固定 userId 验签必须失败，
// 证明出向签名绑定 appKey 而非协议默认值（D14：userId 来源链）。
func TestSignMessage_SM2_UserIdSameSourceAsAppKey(t *testing.T) {
	v := loadGoldenVectors(t)
	suite := mustSuite(t, "WOP-SM2-SM3")
	priv := &privKey{sm2: mustSM2Priv(t, v.Keys.SM2.PrivateDB64)}
	pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	msg := []byte("canonical\nPOST\n/p\n\nx-wop-appkey:test-app-key-01")
	appKey := []byte("test-app-key-01")

	sig, err := signMessage(suite, priv, appKey, msg, nil)
	if err != nil {
		t.Fatalf("SM2 出向签名: %v", err)
	}
	raw := mustDecodeB64u(t, sig)
	if !sm2Verify(pub.sm2, appKey, msg, raw) {
		t.Error("出向签名应以 appKey 为 userId 验签通过（D14 同源）")
	}
	if sm2Verify(pub.sm2, sm2PlatformUserID, msg, raw) {
		t.Error("出向签名不得以平台固定 userId 验签通过（userId 必须 = appKey）")
	}
}

// F7 定长格式校验前置：长度不符按协议类明确拒绝（63/65B 签名、错长 RSA）。
func TestVerifyMessage_LengthPrecheck(t *testing.T) {
	v := loadGoldenVectors(t)
	sm2Suite := mustSuite(t, "WOP-SM2-SM3")
	pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	msg := []byte(v.Inputs.Message)
	good := mustFirstSig(t, v, "sm2-sign-fixedk")

	for _, bad := range []struct {
		name, sig string
	}{
		{"63B（截 r 尾字节）", good[:len(good)-2]},
		{"65B（r 前补零字节）", "AA" + good},
		{"空签名", ""},
	} {
		err := verifyMessage(sm2Suite, pub, msg, bad.sig)
		if err == nil {
			t.Errorf("SM2 %s 应拒绝", bad.name)
			continue
		}
		we := err.(*Error)
		if we.Code != CodeParse {
			t.Errorf("SM2 %s: 错误类 = %s, want CodeParse", bad.name, we.Code)
		}
	}

	rsaSuite := mustSuite(t, "WOP-RSA3072-SHA256")
	rsaPub := &pubKey{}
	var err error
	if rsaPub.rsa, err = parseRSAPublicKey(v.Keys.RSA3072.PublicSpkiB64); err != nil {
		t.Fatal(err)
	}
	if err := verifyMessage(rsaSuite, rsaPub, msg, EncodeB64URL(make([]byte, 383))); err == nil {
		t.Error("383B RSA 签名应拒绝（3072 位恒 384B/512 字符）")
	} else if err.(*Error).Code != CodeParse {
		t.Errorf("RSA 错长: 错误类 = %s, want CodeParse", err.(*Error).Code)
	}
}

// F6 严格无填充：带 '=' 的签名串拒绝（协议类），不是验签失败。
func TestVerifyMessage_B64PaddingRejected(t *testing.T) {
	v := loadGoldenVectors(t)
	suite := mustSuite(t, "WOP-SM2-SM3")
	pub := &pubKey{sm2: mustSM2Pub(t, v.Keys.SM2.PublicPointB64)}
	err := verifyMessage(suite, pub, []byte(v.Inputs.Message), "Si7Uw5eZm0Kii3BuIRLXwMGGOxkwFria8ypcVYXnReV376EVgV0TOkQfm21NUnJZNGM-fV0d0fMF23B0Bm3TFw=")
	if err == nil {
		t.Fatal("带 = 的签名应拒绝")
	}
	if err.(*Error).Code != CodeParse {
		t.Errorf("错误类 = %s, want CodeParse", err.(*Error).Code)
	}
}

// I7：验签失败（密钥不符/内容篡改）对外模糊，仅 CodeSignature + 固定文案。
func TestVerifyMessage_Fuzzy(t *testing.T) {
	v := loadGoldenVectors(t)
	suite := mustSuite(t, "WOP-SM2-SM3")
	msg := []byte(v.Inputs.Message)
	sig := mustFirstSig(t, v, "sm2-sign-fixedk")

	// 公钥与签名方不配对（另一个 SM2 公钥）
	otherPriv, err := generateSM2KeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	err = verifyMessage(suite, &pubKey{sm2: &otherPriv.PublicKey}, msg, sig)
	if err == nil {
		t.Fatal("不配对公钥应验签失败")
	}
	we := err.(*Error)
	if we.Code != CodeSignature || we.Message != verifyFuzzyMessage {
		t.Errorf("I7 违规：code=%s msg=%q", we.Code, we.Message)
	}
}

func publicOf(t *testing.T, v *goldenVectors, suiteID string) string {
	t.Helper()
	switch suiteID {
	case "WOP-RSA3072-SHA256":
		return v.Keys.RSA3072.PublicSpkiB64
	case "WOP-RSA4096-SHA256":
		return v.Keys.RSA4096.PublicSpkiB64
	}
	return v.Keys.SM2.PublicPointB64
}

func generateSM2KeyForTest() (*ecdsa.PrivateKey, error) {
	k, err := randomScalar(nil)
	if err != nil {
		return nil, err
	}
	priv, err := sm2PrivateKeyFromScalar(k)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
