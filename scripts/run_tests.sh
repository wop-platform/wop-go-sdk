#!/usr/bin/env bash
# 工厂测试门（移植四步之四：测试门命令本地化）——go vet + go test 全量 + 覆盖率门禁。
# 用法: scripts/run_tests.sh [--no-lock] [go-test-args...]
#   --no-lock 为工厂链约定旗标（上游 run_tests.sh 的锁语义），本仓无锁，消费并忽略。
# 门组成（对齐 .github/workflows/ci.yml 的 vet/test 命令；退出码域 {0,1}，
# mutations/run.py judge 契约：非 0/1 = 无效运行）：
#   1. go vet ./...                 静态检查
#   2. go test ./... -coverpkg=.    全量测试（覆盖率口径 = 根包协议核心语句）
#   3. 覆盖率门禁：总覆盖率 < 98% 即失败（质量闭环基线 99.1%，下限 98%）
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

ARGS=()
for a in "$@"; do
  [ "$a" = "--no-lock" ] && continue
  ARGS+=("$a")
done

go vet ./... || { echo "GATE: go vet 失败" >&2; exit 1; }

TMPDIR_COVER="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_COVER"' EXIT
go test ./... -covermode=atomic -coverprofile="$TMPDIR_COVER/cover.out" -coverpkg=. \
  "${ARGS[@]+"${ARGS[@]}"}" \
  || { echo "GATE: go test 失败" >&2; exit 1; }

TOTAL="$(go tool cover -func="$TMPDIR_COVER/cover.out" | awk '/^total:/ {sub(/%$/, "", $3); print $3}')"
echo "覆盖率门禁: total=${TOTAL}% (阈值 98%)"
awk -v p="$TOTAL" 'BEGIN { exit (p < 98) ? 1 : 0 }' || {
  echo "GATE: 总覆盖率 ${TOTAL}% 低于阈值 98%" >&2
  exit 1
}
