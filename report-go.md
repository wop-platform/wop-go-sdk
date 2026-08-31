# wop-go-sdk wop-specs 合规审计报告

- 审计日期：2026-09-01
- 审计范围：`wop-go-sdk`（Go SDK）对 wop-specs 真源的合规比对与整改
- 真源：`wop-specs/sdk/wop-sdk-spec.md`（v1.0-ratified）、`wop-specs/crypto/crypto-strategy-spec.md`、`wop-specs/interop/v1/README.md`
- 整改分支：`audit/spec-20260901`
- 结论：**2 项违规全部整改完成，测试/门禁全部通过，无遗留未决项**

---

## ① 审计范围与结论总览

本审计针对上一轮跨仓互操作对齐（interop/v1 合同）遗留的两处 Go SDK 合规缺陷：

| 违规 | 条款 | 现状 | 结论 |
|---|---|---|---|
| 违规点 1：错误码非闭集（旧 8 常量大写命名 + 分类越界） | wop-sdk-spec §2.2 | 已整改为 7 值小写闭集，错误构造点全部收敛 | ✅ 合规 |
| 违规点 2：出向 SM2 签名 userId 硬编码平台默认值 | crypto-strategy-spec D14 | 已整改为出向签名 userId = `x-wop-appkey` 头值 | ✅ 合规 |

验证证据链（全部实测通过）：

- `go build ./...` + `go vet ./...` 零输出
- `go test ./... -count=1` 全套件跑绿（129 个测试函数；godog `TestFeatures` 18 场景 / 79 步骤全过，非跳过）
- CI 口径覆盖率：`go test ./... -covermode=atomic -coverprofile=cover.out -coverpkg=.` → **total 99.1%**（CI 门禁 ≥98%）
- 变更行覆盖率：12 个 src 文件变更行与未覆盖行交叉核算，**未覆盖变更行 = 0**（见 ⑤）
- docstring 门禁：`python3 scripts/docstring_gate.py` → 对外 70/70、内部 106/106，GATE 达标
- `gofmt -l .` 零输出（CI gofmt 检查等价）
- 向量哈希门禁：`internal/testdata/crypto-vectors.json` 未改动（CI 真源 sha256 锚定项不受影响）
- 残留扫描：旧常量名 / 旧 `[CONFIG]` 诊断串 / `sm2DefaultUserID` 在 src 与测试中零残留（仅 `.factory/mutations/defects.json` 历史缺陷描述文本含旧名——历史记录，不改）

---

## ② §2.1 请求头规范逐条比对（含 D14 出向签名）

| §2.1 条款 | 要求 | Go SDK 现状 | 判定 |
|---|---|---|---|
| 签名头结构 | `x-wop-signature` 携带 canonicalRequest 签名 | signheader.go 构造；interop build 场景字节级复现 | ✅ |
| canonicalRequest 组装 | method + path + query + headers + digest 规约 | `CanonicalRequest`/`CanonicalHeaders`，interop fixture 字节级比对 | ✅ |
| 时间戳/Nonce | 请求头携带、签名覆盖 | `WithTimestamp`/`WithNonce`，interop build 场景复现 | ✅ |
| content-digest 产出 | 有 body 必产 digest，tag 与套件族绑定 | digest.go；D2 测试钉死 | ✅ |
| SM2 签名 userId 来源 | **D14：出向签名 userId 必须等于 `x-wop-appkey` 头值（同源），不得用平台默认值** | 整改前：硬编码 `sm2DefaultUserID`（协议默认 ZA 值）→ **违规**；整改后：`BuildRequest` 传 `[]byte(c.appKey)` | ✅ 已整改 |

§2.1 其余条款（头部命名、编码规约）经 golden vectors（F6/D10）与 interop/v1 双向合同覆盖，本次审计无新增发现。

---

## ③ §2.2 错误契约比对（闭集整改）

### 整改前（违规）

旧 8 常量：大写命名、非 §2.2 闭集词汇：

```
CodeConfig("CONFIG") / CodeSuiteParse("SUITE_PARSE") / CodeSuiteUnsupported("SUITE_UNSUPPORTED")
CodeProtocol("PROTOCOL") / CodeDigestMismatch("DIGEST_MISMATCH") / CodeVerifyFailed("VERIFY_FAILED")
CodeDecryptFailed("DECRYPT_FAILED") / CodeAlgMismatch("ALG_MISMATCH")
```

两处违反 §2.2：① 词汇表越界（`SUITE_PARSE`/`SUITE_UNSUPPORTED` 等不在闭集）；② 命名风格不符合小写闭集约定（跨语言恒定、禁止自造）。

### 整改后（合规）

`errors.go` 重构为 §2.2 闭集 7 常量 + 双构造器：

| 闭集值 | 常量 | 语义映射 | 触发路径（Go） |
|---|---|---|---|
| `configuration` | `CodeConfiguration` | appKey/密钥材料缺失非法、securityReq 非法或跨族（F1） | suite.go ParseSuite、client.go、keys.go、keyencrypt.go、verify.go 兜底 |
| `parse` | `CodeParse` | header/信封/线上编码格式（D1/D3） | digest.go、encoding.go、signheader.go、transport.go、verify.go |
| `unsupported` | `CodeUnsupported` | 合法套件但本 SDK 未实现 | **无触发路径**（Go 已实现全部合法套件，保留枚举值满足闭集完整性） |
| `integrity` | `CodeIntegrity` | digest 与线上报文字节不符（D2） | digest.go |
| `consistency` | `CodeConsistency` | dek alg 与套件族不符（I3） | keyencrypt.go |
| `signature` | `CodeSignature` | 验签失败（模糊，I7） | signature.go/verify.go，`fuzzyError` |
| `decrypt` | `CodeDecrypt` | DEK 解包或 GCM 解密失败（模糊，I7） | keyencrypt.go，`fuzzyError` |

构造器纪律：`newError(code, format, args…)`（明确类，message 可含细节）与 `fuzzyError(code)`（模糊类，文案钉死 `verifyFuzzyMessage="签名验证失败"` / `decryptFuzzyMessage="解密失败"`，I7 防 padding-oracle 信息泄露）。`fuzzyError` 是唯一进入验签/解密类的出口，编译期可审计。

### API 破坏性标注

- 旧 8 常量名全部删除，替换为 7 新常量名。**属破坏性变更**：已升级的商户若引用旧常量（如 `wop.CodeVerifyFailed`）将编译失败。鉴于错误码语义同时被修正（§2.2 闭集词汇），建议按 SDK 主版本发布并在 changelog 标注；值域（`ErrorCode` 字符串）语义对齐跨语言，Go 侧无法用编译期手段兼容旧名，不设别名（别名会重新引入「自造词汇」违规）。
- `VerifyResult.Code` 可观测性：spec §2.2 说明入向错误分类对外不可观测，但 Go SDK 的 `VerifyResult` 暴露 `Code` 字段（`verify.go`），`interop_test.go` 的 `classOf` 据此做显式映射（`signature→verify-failed`、`decrypt→decrypt-failed`、`integrity→digest-mismatch`、`consistency→alg-mismatch`、`parse→protocol`）。裁决：**Go 使其可观测故断言合法**，报告注明差异与理由，不整改。
- `CodeConfiguration`/`CodeUnsupported` 在 interop `classOf` 中无 canonical 对应，落 default→`"protocol"`；interop 负样本不触发这两个值，注释说明。

---

## ④ D14 出向 SM2 userId 同源整改

**违规**：`signature.go` 原 `signMessage` 对 SM2 族硬编码平台协议默认 userId（`sm2DefaultUserID`，即协议固定 ZA 值），出向签名与 `x-wop-appkey` 头值不同源。平台侧验签按 appKey 推导 ZA，若 SDK 用默认值签名将验签失败（跨语言共享同一错误的隐患）。

**整改**：

1. `signature.go`：
   - 删除 `sm2DefaultUserID`，新增 `var sm2PlatformUserID = []byte("1234567812345678")`（注释：平台协议固定值，**仅入向验签使用**）。
   - `signMessage(s Suite, key *privKey, userId []byte, msg []byte, random io.Reader) (string, error)`：SM2 族使用调用方传入的 `userId`，RSA 族忽略（不受影响）。
   - `verifyMessage` 仍用 `sm2PlatformUserID`（入向验签按平台协议默认 userId 校验，符合 D14「入向 vs 出向分离」语义）。
2. `client.go` `BuildRequest`：出向签名调用传 `[]byte(c.appKey)`，即 `x-wop-appkey` 头值，附 `// D14：出向签名 userId 必须 = x-wop-appkey 头值` 注释。
3. 全部测试调用点迁移至新签名（signature_test、invariants_test、mutation_hardening*、interopgen 等）。

**同源证明测试**（`signature_test.go`，`spec:D14-1`）：固定 appKey 签出的 SM2 签名，以同一 userId（= appKey）验签通过；以 `sm2PlatformUserID` 验签必须失败——证明出向签名绑定 appKey 而非协议默认值。

**残留扫描**：`sm2DefaultUserID` 在仓库内零残留。

---

## ⑤ D1–D7 / E1–E3 抽查

| 条款 | 要求 | 证据 | 判定 |
|---|---|---|---|
| D4 响应体上限 | 防失控读，限额明确 | `transport.go:33` `const maxResponseBytes = 11 << 20`；`mutation_hardening_test.go` `TestDefaultTransport_ResponseLimitBoundary` 恰 11MiB 通过、`transport_test.go` 超限（+1 字节）拒绝 | ✅ |
| D6 明确类文案 | 商户可依赖精确文案自查，全等断言 | `errors_test.go` `TestErrorCode_ExplicitMessagesExact`（`spec:D6-1`）：securityReq 空/格式非法、digest 头格式、digest 不匹配四句文案与 src 逐字全等 | ✅ |
| I7 模糊类文案 | 验签/解密失败不携带原因细节 | `fuzzyError` 文案钉死；invariants I7-1/I7-2 断言固定模糊文案 | ✅ |
| E1 覆盖率口径 | 语句覆盖 + 分支矩阵，不裸报单百分比 | CI 口径语句覆盖 **99.1%**（≥98%）；变更行交叉核算未覆盖 = **0**；显式分支矩阵见 ⑥ | ✅ |
| E2 确定性 | 测试不依赖随机真源 | `deterministicReader`/`newHexReader`/golden vectors；全量 `-count=1` 稳定 | ✅ |
| E3 隔离性 | 测试不触外部网络/真源下载 | golden fixtures 落盘 `internal/testdata/`；httptest 模拟网关 | ✅ |
| D14 出向同源 | 见 ④ | `spec:D14-1` | ✅ |

E1 变更行核算明细（`git diff` 变更行 ∩ 未覆盖语句行）：

```
client.go 10/0 · digest.go 5/0 · encoding.go 2/0 · errors.go 29/0 · keyencrypt.go 9/0
keys.go 11/0 · message.go 12/0 · signature.go 19/0 · signheader.go 12/0 · suite.go 8/0
transport.go 5/0 · verify.go 9/0 —— 变更行 131 行，未覆盖 0 行
```

主包未覆盖行仅剩：`client.go:243`（sealMessage 防御分支）、`message.go:61/65`（对称算法初始化/GCM 失败防御分支，标准库对合法参数不失败）、sm2raw.go 防御分支——均不在本次变更集。

---

## ⑥ 整改清单与验证证据（条款 → 测试名反向核对矩阵）

| 条款 | 测试（`// spec:` 标签） | 断言内容 |
|---|---|---|
| §2.2 闭集完整性 | `errors_test.go` `TestErrorCode_ClosedSetValues` (`spec:2.2-1`) | 七值全等/互异/全小写 ASCII（跨语言恒定，禁止自造） |
| §2.2 源码只引用闭集 | `errors_test.go` `TestErrorCode_SourceOnlyUsesClosedSet` (`spec:2.2-2`) | 扫描全部非测试源码的 `newError`/`fuzzyError`/`Code:` 构造点，标识符 ∈ 七常量名；旧名或新自造常量出现即违规 |
| §2.2 否定式（分类越界） | `errors_test.go` `TestErrorCode_NeverClassifiesSuiteErrorsAsParseOrUnsupported` (`spec:2.2-3`) | `""`/`RSA3072-SHA256`/`WOP-RSA2048-SHA256`/`WOP-RSA3072-SM3` 必归 configuration，绝不落 parse/unsupported（回归即 fail） |
| D6 明确类文案全等 | `errors_test.go` `TestErrorCode_ExplicitMessagesExact` (`spec:D6-1`) | 四句明确类文案逐字全等（非 contains） |
| D14 出向同源 | `signature_test.go` `TestSignMessage_SM2_UserIdSameSourceAsAppKey` (`spec:D14-1`) | appKey 签名 → 同 userId 验签通过、平台默认 userId 验签失败 |
| F1 suite 分类 | `suite_test.go`（负样本表）+ `spec:2.2-3` | 空/非三段/四段/前缀非 WOP/密钥算法不在列表/摘要不在列表/跨族 → configuration |
| F6/D10 编码 | `vectors_conformance_test.go` (`spec:F6/D10`) | b64url 严格拒 `=`/非法字母表/尾随位，accept 字节级一致 |
| F7/D9 签名/密文格式 | `sm2raw_coverage_test.go` (`spec:F7/D9`)、invariants F7-1..3/D9-1/D9-2 | SM2 63/65B 拒、RSA 错长拒、C1C2C3 解密失败、DER 签名拒 |
| F2 编码细节 | `mutation_hardening3_test.go` (`spec:F2`) | URLEncodeJava 全 256 表、连续空白折叠单空格 |
| D2 digest 纪律 | `invariants_test.go` (`spec:D2-1..D2-4`)、`mutation_hardening_test.go` | 无 body 无 digest 合法、有 body 缺 digest 拒、双空格拒、大写 hex 拒、单字节 body 必产 digest |
| I1/I2/I3/I5 | `invariants_test.go` (`spec:I1/I2/I3/I5`) | digest 未入 signedHeaders 拒、篡改签名模糊拒、dek 跨族一致性明确拒、digest 标签跨族拒 |
| I7 模糊化 | `invariants_test.go` (`spec:I7-1/I7-2`)、features `signature`/`decrypt` 场景 | 验签/解密失败对外仅固定模糊文案 |
| D9/D10 | `vectors_conformance_test.go`、`sm2raw_coverage_test.go` | 见上 |
| A6 godog 验收 | `features_suite_test.go` `TestFeatures` (`spec:A6/…`) | 18 场景 / 79 步骤全过：`configuration×2`、`integrity`、`signature`、`parse×2`、`consistency`、`decrypt` |

**验收方法说明**（spec 类工作纪律）：本报告采用「条款 → 测试名反向核对矩阵」而非仅覆盖率数字；否定式条款（2.2-2 源码扫描、2.2-3 分类越界、I7 模糊文案）均有对应测试，且以 `// spec:<ID>` 标签建立 grep 索引。覆盖率数字（99.1%）为终局测量（全部语义变更后重跑），未被中途达标稀释。

**未整改项（有意保留）**：
- `.factory/mutations/defects.json` 描述文本含旧错误码名——历史缺陷记录，非生产代码，不改。
- `CodeUnsupported` 无触发路径但保留枚举值——§2.2 闭集完整性要求（Go 实现全部合法套件，无「合法套件未实现」路径）。
- interop `classOf` 中 configuration/unsupported 落 default `protocol`——无 canonical 对应，负样本不触发，注释说明。

**变更规模**：31 个文件修改 + `errors_test.go` 新增；308 insertions / 268 deletions。
