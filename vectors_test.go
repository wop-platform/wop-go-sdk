package wop

import (
	"encoding/json"
	"os"
	"testing"
)

// 黄金向量 fixture（协议真源字节副本，禁手改；spec 附录 B.2 / D9）。
const vectorsPath = "internal/testdata/crypto-vectors.json"

type goldenVectors struct {
	Inputs struct {
		Message       string `json:"message"`
		SM2UserID     string `json:"sm2UserId"`
		DekPayloadRSA string `json:"dekPayloadRsa"`
		DekPayloadSM2 string `json:"dekPayloadSm2"`
		AESKeyB64u    string `json:"aesKeyB64u"`
		AESIvB64u     string `json:"aesIvB64u"`
		SM4KeyB64u    string `json:"sm4KeyB64u"`
		SM4IvB64u     string `json:"sm4IvB64u"`
		SM2FixedKB64u string `json:"sm2FixedKB64u"`
	} `json:"inputs"`
	Keys struct {
		RSA3072 struct {
			PublicSpkiB64   string `json:"publicSpkiB64"`
			PrivatePkcs8B64 string `json:"privatePkcs8B64"`
		} `json:"rsa3072"`
		RSA4096 struct {
			PublicSpkiB64   string `json:"publicSpkiB64"`
			PrivatePkcs8B64 string `json:"privatePkcs8B64"`
		} `json:"rsa4096"`
		SM2 struct {
			PublicPointB64 string `json:"publicPointB64"`
			PrivateDB64    string `json:"privateDB64"`
		} `json:"sm2"`
	} `json:"keys"`
	Digests []struct {
		ID             string `json:"id"`
		Algorithm      string `json:"algorithm"`
		Input          string `json:"input"`
		ExpectedHex    string `json:"expectedHex"`
		ExpectedHeader string `json:"expectedHeader"`
	} `json:"digest"`
	MessageEncrypt []struct {
		ID            string `json:"id"`
		Algorithm     string `json:"algorithm"`
		KeyB64u       string `json:"keyB64u"`
		IvB64u        string `json:"ivB64u"`
		PlaintextB64u string `json:"plaintextB64u"`
		CipherTagB64u string `json:"cipherTagB64u"`
	} `json:"messageEncrypt"`
	Signature []struct {
		ID              string `json:"id"`
		Key             string `json:"key"`
		Message         string `json:"message"`
		ExpectedSigB64u string `json:"expectedSigB64u"`
		SigLenBytes     int    `json:"sigLenBytes"`
		B64uLen         int    `json:"b64uLen"`
	} `json:"signature"`
	KeyEncrypt []struct {
		ID            string `json:"id"`
		Key           string `json:"key"`
		CipherB64u    string `json:"cipherB64u"`
		ExpectedPlain string `json:"expectedPlaintext"`
		Plaintext     string `json:"plaintext"`
		Params        string `json:"params"`
		Expect        string `json:"expect"`
	} `json:"keyEncrypt"`
	DekPayload []struct {
		ID       string `json:"id"`
		Alg      string `json:"alg"`
		KeyB64u  string `json:"keyB64u"`
		IvB64u   string `json:"ivB64u"`
		Expected string `json:"expected"`
	} `json:"dekPayload"`
	FormatRules []struct {
		ID     string `json:"id"`
		Value  string `json:"value"`
		Expect string `json:"expect"`
		Suite  string `json:"suite"`
	} `json:"formatRules"`
}

func loadGoldenVectors(t *testing.T) *goldenVectors {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("读取黄金向量 fixture 失败：%v", err)
	}
	var v goldenVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("解析黄金向量 fixture 失败：%v", err)
	}
	return &v
}
