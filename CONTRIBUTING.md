# 贡献指南（WOP Go SDK）

## 1. 欢迎与定位

本仓库是 WOP 网关商户侧**官方 Go SDK**（`github.com/wop-platform/wop-go-sdk`），
实现协议真源 `crypto-strategy-spec.md`（v0.3-reviewed）与 `wop-sdk-spec.md`（v1.0-ratified）
的功能面 F1–F9。欢迎贡献，但一切协议行为以 spec 为准——发现 spec 与实现冲突时，
先在 issue 中提出，勿以"既有实现"为由顺延 spec 条款。

- 主分支 `main`，MIT License，版本 v0.1.0
- 组织 `wop-platform`，各语言官方 SDK 共享同一套黄金向量（见 [wop-specs](https://github.com/wop-platform/wop-specs)）

## 2. 开发环境

| 项 | 要求 |
|---|---|
| Go | **1.27**（与 `.github/workflows/ci.yml` 的 `go-version` 和 `go.mod` 一致） |
| 依赖 | 仅白名单：`github.com/emmansun/gmsm`（国密唯一指定库）、`golang.org/x/crypto`、`golang.org/x/sys`（间接）。新增依赖须先在 issue 中说明理由 |
| 系统 | 纯 Go 无 CGO，任意平台可开发；CI 以 ubuntu-latest 为准 |

```bash
git clone git@github.com:wop-platform/wop-go-sdk.git
cd wop-go-sdk
go test ./...   # 首次冒烟
```

## 3. 构建与测试

CI（`.github/workflows/ci.yml`）在 push/PR 时执行以下四道门禁，**本地提交前请用完全相同的命令自查**：

```bash
# 1) gofmt 检查（与 ci.yml 逐字一致）
test -z "$(gofmt -l .)" || (gofmt -l . && exit 1)

# 2) vet
go vet ./...

# 3) 全量测试 + 语句覆盖率（含向量 conformance）
go test ./... -covermode=atomic -coverprofile=cover.out
total=$(go tool cover -func=cover.out | awk '/^total:/ {sub("%","",$3); print $3}')
echo "total statement coverage: ${total}%"
awk -v t="$total" 'BEGIN { if (t+0 < 98) { print "coverage " t "% < 98%"; exit 1 } }'

# 4) 依赖白名单
deps=$(go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' . | sort -u | grep -Ev '^(github.com/wop-platform/wop-go-sdk|github.com/emmansun/gmsm|golang.org/x/crypto|golang.org/x/sys)$' | grep -v '^$' || true)
if [ -n "$deps" ]; then echo "non-whitelisted deps:"; echo "$deps"; exit 1; fi
```

覆盖率门禁：**语句覆盖率 ≥98% 为硬门禁，目标 100%**（当前 98.6%）。覆盖率闭合必须在
所有语义变更完成后终局测量并重跑门禁——中途达标的数字会被后续分支稀释。
Go 无原生分支计数，按 spec §3 约定以显式负向量清单替代分支覆盖口径（见 `invariants_test.go`）。

## 4. 黄金向量纪律

- `internal/testdata/crypto-vectors.json` 是协议真源的字节副本，**禁止手改**——它是各语言
  SDK 唯一的正确性锚，改一个字节就会制造跨语言漂移。
- 新增协议行为的流程：先改网关侧真源 → 真源重新生成全量向量 → 各语言 SDK 仓库同步拷贝 →
  各仓库更新全量消费测试。任何"改向量让测试变绿"的提交一律拒绝。
- 正向量必须**字节级**一致（签名/密文/摘要/DEK 组装）；负向量（篡改签名/密文/摘要、跨族
  digest 标签/securityReq、63/65 字节签名、DER 签名、带 `=` 的 base64url、MGF1-SHA1 陷阱密文、
  C1C2C3 旧国标顺序）**必须全部拒绝**。
- 不变式测试集中在 `invariants_test.go`，逐条加 `// spec:<ID>` 注释索引
  （D2/I1/I2/I3/I5/I7/F2/F7/D9），便于"条款 → 测试名"反向核对；否定式条款
  （如"无 body 时 digest 头缺席合法"）也必须有对应测试。
- 需要确定性输出时使用可测试性钩子（`WithTimestamp`/`WithNonce`/`WithRandom`）；生产代码
  禁止固定随机源——GCM 同密钥下 IV 复用即协议不变式 I4 违规。

## 5. 编码规范

- 格式：`gofmt` 零 diff；静态检查：`go vet ./...` 零告警。遵循 Go 官方惯例：
  error 显式返回值、导出符号带 doc comment、包级公共 API 保持精简。
- 协议语义必须与 spec 功能面对齐：
  - **F1** 套件配置与解析：三套件白名单（`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`），跨族/非法拒绝
  - **F2** canonicalRequest：5 段 `\n`；header 值 Java-URLEncoder 语义（空格→`%20` 等）
  - **F3** 结构化 `x-wop-sign`：商户私钥加签（出向），平台公钥验签（响应与回调）
  - **F4** `x-wop-content-digest`：`alg 小写hex` 恰一空格；算法随套件族；无 body 缺席（D2）；有 body 必传必入签（I1）
  - **F5** L2 数字信封：AES-256-GCM / SM4-GCM 全文加密；DEK 载荷 `alg$key$iv`；RSA-OAEP 显式双 SHA-256 + 空 label；SM2 密文 C1C3C2
  - **F6** 响应/回调校验顺序固定：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密
  - **F7** 线上字节格式：base64url 无填充（拒收 `=`）；SM2 签名裸 `r‖s` 64 字节；RSA 公钥 SPKI / SM2 未压缩点
  - **F9** 防重放辅助：CSPRNG nonce、毫秒时间戳、expiredSeconds 组装
- 错误模糊化（**I7**）：验签/解密类失败对外只给固定模糊文案（`VERIFY_FAILED` /
  `DECRYPT_FAILED`，防 oracle）；配置/解析/协议类错误明确指出问题；`DIGEST_MISMATCH`、
  `ALG_MISMATCH` 明确。新增错误码先对照 spec I7 分类。

## 6. 提交规范

Conventional commits，**body 用中文**说明动机与影响：

```
feat(sign): 支持 OAEP label 自定义

网关侧 §6 更新后 label 需可配置；默认仍为空 label，向量全部不变。
```

- 类型：`feat` / `fix` / `test` / `docs` / `chore`（协议行为变更只允许 `feat`/`fix`，且必须附 spec 条款号）
- 一次提交一件事；禁止"顺手"改向量 fixture 或无关重构混入

## 7. PR 流程

1. 从 `main` 拉分支开发，完成后向 `main` 发 PR
2. CI 必须全绿：gofmt + go vet + 测试 + **覆盖率 ≥98%** + 依赖白名单 + 向量 conformance
3. 涉及协议行为的变更：PR 描述中附"spec 条款 → 测试名"反向核对矩阵，reviewer 逐条复核
4. 至少一名 reviewer 批准后合并；squash merge 保持主历史整洁

## 8. 发布流程

Go 模块**打 tag 即发布**——无需任何发布凭证，不走应用商店式发布步骤：

1. 确认 `main` CI 全绿，本地完整跑一遍第 3 节四道门禁
2. 打 tag 并推送：`git tag vX.Y.Z && git push origin vX.Y.Z`（遵循语义化版本；破坏性变更升次版本）
3. tag 推送自动触发 `.github/workflows/release.yml`：复用 ci.yml 的完整命令做发布前验证
   （gofmt / go vet / go test + 覆盖率门禁 / 依赖白名单）
4. 验证通过后无需人工动作：`proxy.golang.org` 会自动索引该 tag，下游 `go get github.com/wop-platform/wop-go-sdk@vX.Y.Z` 即可用，pkg.go.dev 文档随代理同步
5. 注意 Go 生态版本不可撤销：tag 一旦被代理缓存，同号重打不会生效。发布后发现缺陷
   只能修复后发新 patch 版本；验证失败时**立即删除 tag** 争取在代理缓存前止损

发布不涉及任何 GitHub Secrets（无 NPM_TOKEN 类凭证需求），仓库与 workflow 中不得出现任何明文凭证。
