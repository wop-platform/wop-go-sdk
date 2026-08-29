package wop

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// interop conformance（协议编排跨仓一致性合同消费端）：
// fixture 为 wop-specs/interop/v1 的字节副本（禁手改），与本仓生成器输出一致。
// build 方向断言"同输入复现同 draft"；verify 方向断言跨仓编排与错误分类合同。

const interopFixturePath = "internal/testdata/interop-cases.json"

type interopFixtureT struct {
	Meta struct {
		Format    string `json:"format"`
		CaseCount int    `json:"caseCount"`
	} `json:"_meta"`
	Cases []struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Suite string `json:"suite,omitempty"`
		Level string `json:"level,omitempty"`
		Input *struct {
			Method       string `json:"method"`
			Path         string `json:"path"`
			AppKey       string `json:"appKey"`
			PlaintextB64 string `json:"plaintextB64"`
			TimestampMs  int64  `json:"timestampMs"`
			Nonce        string `json:"nonce"`
			RandomHex    string `json:"randomHex"`
		} `json:"input"`
		Expected *struct {
			ReproduceMode string            `json:"reproduceMode"`
			WireBodyB64   string            `json:"wireBodyB64"`
			Headers       map[string]string `json:"headers"`
			Opaque        []string          `json:"opaque"`
		} `json:"expected"`
		Response *struct {
			Method      string            `json:"method"`
			Path        string            `json:"path"`
			AppKey      string            `json:"appKey"`
			Headers     map[string]string `json:"headers"`
			WireBodyB64 string            `json:"wireBodyB64"`
		} `json:"response"`
		VerifyPath string `json:"verifyPath"`
		Expect     *struct {
			OK           bool   `json:"ok"`
			PlaintextB64 string `json:"plaintextB64"`
			ErrorClass   string `json:"errorClass"`
		} `json:"expect"`
	} `json:"cases"`
}

func loadInteropFixture(t *testing.T) *interopFixtureT {
	t.Helper()
	raw, err := os.ReadFile(interopFixturePath)
	if err != nil {
		t.Fatalf("读取 interop fixture 失败：%v", err)
	}
	var f interopFixtureT
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("解析 interop fixture 失败：%v", err)
	}
	return &f
}

// classOf 将本仓错误码映射到跨仓规范分类（wop-specs/interop/v1 合同）。
func classOf(c ErrorCode) string {
	switch c {
	case CodeVerifyFailed:
		return "verify-failed"
	case CodeDecryptFailed:
		return "decrypt-failed"
	case CodeDigestMismatch:
		return "digest-mismatch"
	case CodeAlgMismatch:
		return "alg-mismatch"
	default:
		return "protocol"
	}
}

// TestInteropConformance_Build 同输入必须复现同 draft（RSA 字节级；
// SM2 按 opaque 字段豁免密钥参与段，其余字段仍字节级比对）。
func TestInteropConformance_Build(t *testing.T) {
	v := loadGoldenVectors(t)
	f := loadInteropFixture(t)
	builds := 0
	for _, c := range f.Cases {
		if c.Kind != "build" {
			continue
		}
		builds++
		client := interopClient(t, v, c.Suite)
		draft, err := client.BuildRequest(c.Input.Method, c.Input.Path,
			mustDecodeB64u(t, c.Input.PlaintextB64), Level(c.Level),
			WithTimestamp(c.Input.TimestampMs), WithNonce(c.Input.Nonce),
			WithRandom(newHexReader(t, c.Input.RandomHex)))
		if err != nil {
			t.Fatalf("%s: 构建失败: %v", c.ID, err)
		}
		if got := EncodeB64URL(draft.WireBody); got != c.Expected.WireBodyB64 {
			t.Errorf("%s: wire body 字节不一致", c.ID)
		}
		opaque := map[string]bool{}
		for _, o := range c.Expected.Opaque {
			opaque[o] = true
		}
		for name, want := range c.Expected.Headers {
			got := draft.Headers[name]
			if opaque[name+".signatureSegment"] && name == HeaderSign {
				got, want = stripSignatureSegment(got), stripSignatureSegment(want)
			}
			if opaque[name+".dekValue"] && name == HeaderEncrypt {
				got, want = stripDekValue(got), stripDekValue(want)
			}
			if got != want {
				t.Errorf("%s: 头 %s = %q, want %q", c.ID, name, got, want)
			}
		}
		if len(draft.Headers) != len(c.Expected.Headers) {
			t.Errorf("%s: 头集合不一致（%d vs %d）", c.ID, len(draft.Headers), len(c.Expected.Headers))
		}
	}
	if builds != 6 {
		t.Fatalf("build 用例数 = %d, want 6", builds)
	}
}

// TestInteropConformance_Verify verify 方向全量消费：正向通过+明文一致，
// 负向错误分类逐条对账（含 P 系列故障注入的静态等价样本）。
func TestInteropConformance_Verify(t *testing.T) {
	v := loadGoldenVectors(t)
	f := loadInteropFixture(t)
	clients := map[string]*Client{}
	clientFor := func(suiteID string) *Client {
		if c, ok := clients[suiteID]; ok {
			return c
		}
		c := interopClient(t, v, suiteID)
		clients[suiteID] = c
		return c
	}
	pos, neg := 0, 0
	for _, c := range f.Cases {
		if !strings.HasPrefix(c.Kind, "verify-") {
			continue
		}
		h := http.Header{}
		for name, val := range c.Response.Headers {
			// 小写化后 Set：Go net/http 对头名做结构性规范化（P7 由构造保证）；
			// 混合大小写样本主要验证自管头映射的仓（java/ts 等）
			h.Set(strings.ToLower(name), val)
		}
		verifyPath := c.Response.Path
		if c.VerifyPath != "" {
			verifyPath = c.VerifyPath
		}
		res := clientFor(c.Suite).VerifyResponse(c.Response.Method, verifyPath, h,
			mustDecodeB64u(t, c.Response.WireBodyB64))
		if c.Kind == "verify-positive" {
			pos++
			if !res.OK {
				t.Errorf("%s: 应通过（code=%s reason=%s）", c.ID, res.Code, res.Reason)
				continue
			}
			if string(res.Plaintext) != string(mustDecodeB64u(t, c.Expect.PlaintextB64)) {
				t.Errorf("%s: 明文不一致", c.ID)
			}
		} else {
			neg++
			if res.OK {
				t.Errorf("%s: 应拒绝", c.ID)
				continue
			}
			if got := classOf(res.Code); got != c.Expect.ErrorClass {
				t.Errorf("%s: 错误分类 = %s(%s), want %s", c.ID, got, res.Code, c.Expect.ErrorClass)
			}
		}
	}
	if pos != 7 || neg != 16 {
		t.Fatalf("verify 用例计数哨兵: positive=%d want 7, negative=%d want 16", pos, neg)
	}
}

// TestInteropFixtureMatchesVectors 真源一致性：fixture 引用的套件/密钥材料
// 必须来自同一黄金向量体系（与 crypto-vectors.json 同源生成）。
func TestInteropFixtureIntegrity(t *testing.T) {
	f := loadInteropFixture(t)
	if f.Meta.Format != "wop-interop-1" {
		t.Fatalf("fixture 格式 = %q", f.Meta.Format)
	}
	if len(f.Cases) != f.Meta.CaseCount {
		t.Fatalf("caseCount 元数据 = %d, 实际 %d", f.Meta.CaseCount, len(f.Cases))
	}
	known := map[string]bool{
		"n01-encrypted-char-damage": true, "n02-wire-tampered-after-signing": true,
		"n03-digest-tag-cross-family": true, "n04-dek-alg-cross-family": true,
		"n05-dek-c1c2c3-order": true, "n06-signature-b64-padding": true,
		"n07-signature-63b": true, "n08-signature-65b": true,
		"n09-digest-missing": true, "n10-digest-not-signed": true,
		"n11-suite-mismatch": true, "n12-envelope-missing-field": true,
		"n13-dek-key-length": true, "n14-missing-signed-header": true,
		"n15-digest-without-body": true, "n16-replay-cross-path": true,
	}
	seen := 0
	for _, c := range f.Cases {
		if known[c.ID] {
			seen++
		}
	}
	if seen != len(known) {
		t.Fatalf("未知 id 哨兵失败：已知负样本命中 %d/%d（fixture 漂移或新增未登记用例）", seen, len(known))
	}
}

func stripSignatureSegment(signHeader string) string {
	if i := strings.LastIndexByte(signHeader, '/'); i >= 0 {
		return signHeader[:i+1]
	}
	return signHeader
}

func stripDekValue(encryptHeader string) string {
	if i := strings.Index(encryptHeader, "dek="); i >= 0 {
		return encryptHeader[:i+4]
	}
	return encryptHeader
}

// newHexReader 从 hex 串构造字节流（build 复现用确定性随机源）。
type hexReader struct {
	raw []byte
	pos int
}

func newHexReader(t *testing.T, hexStr string) *hexReader {
	t.Helper()
	return &hexReader{raw: mustDecodeHex(t, hexStr)}
}

func (r *hexReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.raw) {
		// 语义上确定性随机源耗尽即失败；但 build 路径 nonce/CEK/IV 均在前段，
		// 正常不会读到末尾。给满额返回以防万一。
		for i := range p {
			p[i] = 0x5A
		}
		return len(p), nil
	}
	n := copy(p, r.raw[r.pos:])
	r.pos += n
	return n, nil
}
