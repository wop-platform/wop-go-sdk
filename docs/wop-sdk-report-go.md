# wop-go-sdk 完成报告

日期：2026-08-29 ｜ 仓库：`github.com/wop-platform/wop-go-sdk`（分支 main，未推送，无 tag）
Module：`github.com/wop-platform/wop-go-sdk`（go 1.27）｜ 版本 v0.1.0（README 声明，按任务书不打 git tag）

## 1. 交付概览

核心包 `wop`（module 根，13 个源文件）：

| 文件 | 职责 |
|---|---|
| suite.go | securityReq 三套件解析（F1，单一注册表 D13，跨族/非法分类拒绝） |
| encoding.go | base64url 无填充严格解码 / 小写 hex / Java-URLEncoder 语义 / TrimAll |
| canonical.go | canonicalRequest 5 段拼装 + canonicalHeaders（F2，与网关 CanonicalRequestBuilder 逐字节对齐） |
| digest.go | 套件族路由摘要 + x-wop-content-digest codec（F4/D2/I5） |
| keys.go | 密钥材料解析（D12：RSA SPKI/PKCS8、SM2 65B 点/32B 标量）+ 位数强校验 |
| sm2raw.go | SM2 原始协议数学（D9 三钉：裸 r‖s / C1C3C2 / KDF；ZA、try-风格重试） |
| signature.go | 签名/验签策略（F3/F7：RSA PKCS#1 v1.5 / SM3withSM2，定长前置校验） |
| keyencrypt.go | DEK 包装（F5③：OAEP 双 SHA-256+空 label / SM2） |
| message.go | L2 报文对称加密（F5②：AES-256-GCM / SM4-GCM，ciphertext‖tag）+ DEK 载荷 codec |
| signheader.go | x-wop-sign 结构头解析/组装 + L2 信封 JSON + x-wop-encrypt |
| client.go | Config/Client/BuildRequest（L0/L2、单一随机源、幂等重放）+ Do 一站式 |
| verify.go | F6 管线：结构前置（D2/I1）→ 验签（I2）→ digest 复核 → DEK 解包 → alg 族比对（I3）→ bulk 解密 |
| transport.go | Transport 接口 + DefaultTransport + TransportFunc + RoundTripperTransport 桥接 |
| errors.go | wop.Error 错误模型（8 类 Code；验签/解密模糊 I7） |

依赖：直接依赖仅 `github.com/emmansun/gmsm v0.44.1`（传递 x/crypto、x/sys，均白名单内）。
`go list -deps -f '{{if .Module}{{.Module.Path}{{end}}' . | sort -u` 过滤后为空 → 零非白名单依赖。

## 2. 验收四件套原文

### 2.1 全量测试绿（含向量 conformance 套件）

```
$ go test ./... -covermode=atomic -coverprofile=cover.out
ok  	github.com/wop-platform/wop-go-sdk	0.595s	coverage: 98.6% of statements
```

87 个测试用例（含 6 个 conformance 套件 + 1 个不变式矩阵），86 PASS + 1 子断言组全绿；`-count=3` 重复运行稳定。

### 2.2 覆盖率报告原文（语句 ≥98% + 负向量清单口径）

```
$ go test ./... -covermode=atomic -coverprofile=cover.out && go tool cover -func=cover.out
github.com/wop-platform/wop-go-sdk/canonical.go:10:	CanonicalHeaders		100.0%
github.com/wop-platform/wop-go-sdk/canonical.go:42:	CanonicalRequest		100.0%
github.com/wop-platform/wop-go-sdk/canonical.go:50:	nz				100.0%
github.com/wop-platform/wop-go-sdk/client.go:61:	NewClient			100.0%
github.com/wop-platform/wop-go-sdk/client.go:115:	Suite				100.0%
github.com/wop-platform/wop-go-sdk/client.go:131:	WithTimestamp			100.0%
github.com/wop-platform/wop-go-sdk/client.go:136:	WithNonce			100.0%
github.com/wop-platform/wop-go-sdk/client.go:141:	WithRandom			100.0%
github.com/wop-platform/wop-go-sdk/client.go:147:	BuildRequest			100.0%
github.com/wop-platform/wop-go-sdk/client.go:228:	sealEnvelope			94.1%
github.com/wop-platform/wop-go-sdk/client.go:251:	sortStrings			100.0%
github.com/wop-platform/wop-go-sdk/client.go:263:	Do				100.0%
github.com/wop-platform/wop-go-sdk/digest.go:17:	Digest				100.0%
github.com/wop-platform/wop-go-sdk/digest.go:29:	DigestHeaderValue		100.0%
github.com/wop-platform/wop-go-sdk/digest.go:35:	ParseContentDigest		100.0%
github.com/wop-platform/wop-go-sdk/digest.go:46:	ValidateContentDigestHeader	100.0%
github.com/wop-platform/wop-go-sdk/digest.go:60:	ValidateContentDigest		100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:15:	EncodeB64URL			100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:21:	DecodeB64URL			100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:33:	LowerHex			100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:39:	TrimAll				100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:48:	collapseWhitespace		100.0%
github.com/wop-platform/wop-go-sdk/encoding.go:70:	URLEncodeJava			100.0%
github.com/wop-platform/wop-go-sdk/errors.go:54:	Error				100.0%
github.com/wop-platform/wop-go-sdk/errors.go:59:	newError			100.0%
github.com/wop-platform/wop-go-sdk/errors.go:64:	fuzzyError			100.0%
github.com/wop-platform/wop-go-sdk/keyencrypt.go:18:	wrapDEKPayload			100.0%
github.com/wop-platform/wop-go-sdk/keyencrypt.go:46:	unwrapDEKPayload		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:21:		decodeKeyMaterial		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:43:		parseRSAPublicKey		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:59:		parseRSAPrivateKey		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:76:		parseSM2PublicKey		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:92:		parseSM2PrivateKey		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:109:		validateRSAKeySize		100.0%
github.com/wop-platform/wop-go-sdk/keys.go:113:		validateRSASize			100.0%
github.com/wop-platform/wop-go-sdk/message.go:19:	sealMessage			100.0%
github.com/wop-platform/wop-go-sdk/message.go:31:	openMessage			100.0%
github.com/wop-platform/wop-go-sdk/message.go:46:	newMessageGCM			85.7%
github.com/wop-platform/wop-go-sdk/message.go:76:	buildDekPayload			100.0%
github.com/wop-platform/wop-go-sdk/message.go:88:	parseDekPayload			100.0%
github.com/wop-platform/wop-go-sdk/message.go:115:	matchesSuite			100.0%
github.com/wop-platform/wop-go-sdk/signature.go:32:	signMessage			100.0%
github.com/wop-platform/wop-go-sdk/signature.go:58:	verifyMessage			100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:24:	authString			100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:29:	ParseSignHeader			100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:72:	parseSignedHeaders		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:85:	buildSignHeader			100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:93:	buildEncryptHeader		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:99:	parseEncryptHeader		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:113:	isStrictB64URLChars		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:132:	wrapEncryptedBody		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:137:	extractEncryptedBody		100.0%
github.com/wop-platform/wop-go-sdk/signheader.go:149:	headerValue			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:19:	sm2Curve			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:30:	pad32				100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:36:	sm2CurveN			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:39:	sm2ZA				100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:60:	sm2E				100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:68:	randomScalar			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:90:	sm2Sign				93.3%
github.com/wop-platform/wop-go-sdk/sm2raw.go:116:	sm2SignTry			88.2%
github.com/wop-platform/wop-go-sdk/sm2raw.go:140:	sm2Verify			92.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:169:	sm2KDF				100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:193:	sm2Encrypt			92.3%
github.com/wop-platform/wop-go-sdk/sm2raw.go:216:	sm2EncryptTry			97.4%
github.com/wop-platform/wop-go-sdk/sm2raw.go:252:	sm2Decrypt			97.3%
github.com/wop-platform/wop-go-sdk/sm2raw.go:294:	concat32			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:301:	equalBytes			100.0%
github.com/wop-platform/wop-go-sdk/sm2raw.go:313:	sm2PrivateKeyFromScalar		100.0%
github.com/wop-platform/wop-go-sdk/suite.go:57:		ParseSuite			100.0%
github.com/wop-platform/wop-go-sdk/suite.go:84:		SecurityReq			100.0%
github.com/wop-platform/wop-go-sdk/suite.go:87:		Family				100.0%
github.com/wop-platform/wop-go-sdk/suite.go:90:		KeyBits				100.0%
github.com/wop-platform/wop-go-sdk/suite.go:93:		SignAlgorithm			100.0%
github.com/wop-platform/wop-go-sdk/suite.go:96:		MessageAlgorithm		100.0%
github.com/wop-platform/wop-go-sdk/suite.go:99:		KeyWrapAlgorithm		100.0%
github.com/wop-platform/wop-go-sdk/suite.go:102:	DigestTag			100.0%
github.com/wop-platform/wop-go-sdk/suite.go:105:	IsSM2				100.0%
github.com/wop-platform/wop-go-sdk/suite.go:108:	cekLen				100.0%
github.com/wop-platform/wop-go-sdk/suite.go:117:	signatureLen			100.0%
github.com/wop-platform/wop-go-sdk/transport.go:36:	Send				100.0%
github.com/wop-platform/wop-go-sdk/transport.go:78:	Send				100.0%
github.com/wop-platform/wop-go-sdk/transport.go:82:	RoundTripperTransport		100.0%
github.com/wop-platform/wop-go-sdk/verify.go:19:	verifyFail			100.0%
github.com/wop-platform/wop-go-sdk/verify.go:29:	VerifyResponse			100.0%
github.com/wop-platform/wop-go-sdk/verify.go:35:	VerifyCallback			100.0%
github.com/wop-platform/wop-go-sdk/verify.go:44:	verify				100.0%
github.com/wop-platform/wop-go-sdk/verify.go:130:	containsHeader			100.0%
total:							(statements)			98.6%
```

分支口径（spec §3 约定，Go 无原生分支计数）：`invariants_test.go` 显式负向量分支清单矩阵
（`spec:<ID>` 注释索引，D2-1/D2-3/D2-4/I1/I2/I3/I5×2/I7×2/F7-1/F7-2/F7-3/D9-1/D9-2/F2 共 16 条 × 期望错误分类逐条对账）。

### 2.3 README 双语存在性

```
$ ls -l README.md README.en.md LICENSE internal/testdata/crypto-vectors.json
-rw-r--r--  1 user  staff  17792 Aug 29 00:16 internal/testdata/crypto-vectors.json
-rw-r--r--  1 user  staff   1069 Aug 29 00:16 LICENSE
-rw-r--r--  1 user  staff   6153 Aug 29 00:54 README.en.md
-rw-r--r--  1 user  staff   5978 Aug 29 00:54 README.md
```

fixture 为协议真源字节副本（sha256 `0e5b89e5…e8ff48` 与协议真源仓库 docs/crypto-vectors.json 一致，禁手改）。
四段必备齐备：快速开始 / 密钥准备（D12）/ L0+L2 示例 / 向量自测说明（含覆盖率命令）。

### 2.4 git log（全 conventional，中文 body）

```
$ git log --oneline
de97346 docs: 双语 README（中文默认）与 CI 白名单检查修正
c5cc3cd test(wop): 不变式负分支清单矩阵与覆盖率闭合 98.6%
40e424c test(wop): 黄金向量 conformance 总套件（A1/A2）
04e9aa7 feat(wop): Transport httptest 覆盖与 Client.Do 一站式调用
7e30974 feat(wop): F6 验签解密管线与 I7 模糊化（F6/I2/I3/I5/I7/D2/D3）
0e3b48f feat(wop): Client 配置/BuildRequest 与 Transport 适配层
102be2c feat(wop): x-wop-sign 结构头与 L2 信封编解码
5422192 feat(wop): DEK 包装与 L2 报文对称加密（F5）
a4b998a feat(wop): 签名/验签策略（F3/F7/I7）
d8b89dd feat(wop): SM2 原始协议数学（D9 三钉锚定）
c31d76d feat(wop): 密钥材料解析（F1 前置/D12）
36030d3 feat(wop): 摘要策略与 x-wop-content-digest（F4/D2/I5）
bdee553 feat(wop): 线上编码与 canonicalRequest 构造（F2）
eadcc41 chore: 初始化 Go module、MIT License、向量 fixture 与 CI
```

TDD 红-绿推进：每个 feat/test 提交前均先跑红（未定义符号/断言失败）再转绿，全程 gofmt 干净、go vet 零告警。

## 3. spec 条款 → 测试名反向核对矩阵

| 条款 | 要求 | 测试名（grep 可核） |
|---|---|---|
| F1 | 套件解析/跨族/非法拒绝 | TestParseSuite_ValidSuites / TestParseSuite_Rejects / TestParseSuite_TrimsWhitespace / TestNewClient_ConfigValidation |
| F2 | canonicalRequest 5 段 + Java-URLEncoder | TestCanonicalRequest / TestCanonicalHeaders / TestURLEncodeJava / TestTrimAll |
| F2(MGF1) | OAEP 双 SHA-256 显式参数 | TestUnwrapDEK_OAEPVectors（mgf1sha1-trap 必败） |
| F3 | 结构化 x-wop-sign 双向 | TestSignHeader_BuildParseRoundtrip / TestParseSignHeader_Strict / TestSignMessage_RSAVectors_ByteLevel / TestSignVerifyMessage_SM2Roundtrip |
| F4/D2 | digest 算法随族/恰一空格/小写 hex | TestDigest_VectorByteLevel / TestParseContentDigest_Strict / TestValidateContentDigest_FamilyCoupling / TestValidateContentDigest_Match |
| D2 缺席 | 无 body → 头缺席；有 body 必传必入签 | TestBuildRequest_L0_NoBody / TestVerifyResponse_D2Rules / TestVerifyResponse_DigestNotSigned_Reject(I1) |
| F5 | L2 信封 + DEK alg$key$iv + OAEP/SM2 | TestSealMessage_VectorByteLevel / TestOpenMessage_RoundtripAndTamper / TestWrapUnwrapDEK_Roundtrip / TestDekPayload_BuildParseVector / TestParseDekPayload_Rejects / TestBuildRequest_L2 / TestEncryptHeaderAndEnvelope |
| F6 顺序 | 验签→digest→解包→族比对→解密 | TestVerifyResponse_TamperedSignature_Fuzzy / TestVerifyResponse_TamperedBody_DigestMismatch / TestVerifyResponse_AlgMismatchBeforeDecrypt / TestVerifyResponse_GCMFailure_Fuzzy / TestVerifyResponse_L0_L2_Happy / TestVerifyCallback_URLPathExtraction |
| F7 | base64url 无填充拒 =、SM2 64B、RSA SPKI | TestB64URL / TestVerifyMessage_LengthPrecheck（63/65B/错长 RSA） / TestVerifyMessage_B64PaddingRejected / TestLowerHex |
| F8 | 向量字节级 + 负向量全拒 | TestVectorConformance_Digest / _MessageEncrypt / _Signature / _KeyEncrypt / _DekPayload / _FormatRules（含条数哨兵） |
| F9 | nonce/timestamp/expiredSeconds 组装 | TestBuildRequest_L0 / TestBuildRequest_ExpiredSecondsConfig / TestBuildRequest_DeterministicReplay |
| I1 | digest 必入 signedHeaders | TestVerifyResponse_DigestNotSigned_Reject |
| I2 | 先验签后解密 | TestVerifyResponse_TamperedSignature_Fuzzy（签名坏 → 验签类，不触解密） |
| I3 | 族比对先于 bulk 解密 | TestVerifyResponse_AlgMismatchBeforeDecrypt（垃圾密文仍报 ALG_MISMATCH） |
| I4 | 同密钥 IV 永不复用 | 结构断言：IV 生成点唯一（client.sealEnvelope 内 io.ReadFull 唯一 CSPRNG 出口）；随机性不可确定性构造（spec 10.1 I4 例外条款），WithRandom 仅联调钩子并文档警告 |
| I5 | 跨族互斥贯穿三处 | TestParseSuite_Rejects（securityReq）/ TestValidateContentDigest_FamilyCoupling（digest 标签）/ TestVerifyResponse_AlgMismatchBeforeDecrypt（dek alg） |
| I6 | 套件原子装配 | TestNewClient_ConfigValidation（配置期全量校验，请求期无半装配窗口） |
| I7 | verify/decrypt 对外模糊 | TestVerifyMessage_Fuzzy / TestUnwrapDEK_FuzzyOnFailure / TestOpenMessage_RoundtripAndTamper / TestVerifyResponse_GCMFailure_Fuzzy + TestInvariantNegativeBranchMatrix 文案钉死断言 |
| D9 | SM2 三钉（r‖s/C1C3C2/禁 DER） | TestSM2Sign_FixedK_Vector / TestSM2Encrypt_FixedK_Vector / TestSM2Decrypt_VectorAndNegatives（C1C2C3 拒）/ 矩阵 D9-2（DER 长度拒） |
| D10/D12 | 密钥分发编码/小写 hex | TestParseRSAKeys_VectorMaterial / TestParseRSAKeys_Rejects / TestParseSM2Keys_VectorMaterial / TestParseSM2Keys_Rejects / TestValidateRSAKeySize |
| Transport | 接口+默认实现+RoundTripper 桥接 | TestDefaultTransport_SendsDraft / TestClient_Do_EndToEnd_L0_L2（httptest，RSA+SM2 双套件） / TestRoundTripperTransport_Bridge / TestTransportFunc_Mock / TestDefaultTransport_Errors / TestClient_Do_Non2xxPassthrough / TestClient_Do_VerifyFailureSurfaces |

## 4. 纪律对账

- **向量唯一正确性锚**：SM2/SM4 算法（自研协议编排于 gmsm 曲线运算之上）对黄金向量字节级断言；RSA 签名 PKCS#1 v1.5 确定性 → 向量直接字节钉。负向量 63/65B、带 =、跨族、C1C2C3、tamper、MGF1-SHA1 陷阱全拒。
- **覆盖率**：语句 98.6% ≥ 98%（-covermode=atomic）。剩余 1.4% 为密码学防御分支（GB/T 强制要求的 r=0/s=0/KDF 全零重试条件，概率 2^-256 不可确定性构造）与 2 处长度前置后不可达的初始化兜底。
- **gofmt 干净**（`gofmt -l .` 空输出）、`go vet` 零告警、CI（ci.yml：gofmt/vet/覆盖率门禁/依赖白名单）。
- **不推送**：`git status` 干净，main 未设 remote；**无 tag**。

## 5. 已知边界与说明

1. **VerifyResponse 不校验时间窗/nonce 重复**：F6 定义为校验管线本身；时效重放类（spec 10.2）由商户按响应 timestamp/nonce 头自行比对（README 已注明）。网关侧才是强制执行点。
2. **canonicalQueryString 恒空串**：网关仅 POST（SignFilter 注释钉死），SDK 对齐；GET 场景分隔空行保留。
3. **结构前置校验先于验签**（D2 缺失/I1 缺签）：均为不依赖密钥的公开协议知识，符合 10.2 明确/模糊分界原则；digest 的格式/族/值复核仍按 F6 在验签之后。
4. **SM2 实现路径**：协议编排（ZA/KDF/签名等式/信封拼装）自研钉死线上字节，曲线运算与 SM3/SM4 由 emmansun/gmsm 提供——这是 B.1 唯一指定路径的要求，向量字节级一致即证明。
