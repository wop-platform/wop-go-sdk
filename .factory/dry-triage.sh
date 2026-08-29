#!/usr/bin/env bash
# dry-triage.sh — triage 裁决干跑（无链副作用：不打标/不评论/不租约/不落 worktree）
#
# 动机（2026-08-27 夜，advisory）：fix-issue.sh --dry-run 只打印编排路径
# （run_node/run_triage 在 DRY=1 下直接 return 0），不产出真实裁决。
# 本脚本逐字复刻 fix-issue.sh run_triage 的 prompt 构造与隔离调用
# （同 prompts/triage.md、同 omp-isolated.yml、同 factory_lib parse），
# 仅省去链的标签/评论/租约副作用——用于预判真实跑链的裁决结果。
#
# 用法: bash dry-triage.sh <issue-number> ...
set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
# ADR-008：issue 读取走 hosting 抽象（需 hosting.env 配置）
[ -f "${REPO}/.factory/hosting.env" ] && . "${REPO}/.factory/hosting.env"
HOST="python3 ${REPO}/.factory/hosting.py"
OUT="${REPO}/.factory/artifacts/dry-triage"
mkdir -p "${OUT}"

for ISSUE in "$@"; do
  DIR="$(mktemp -d)"
  trap 'rm -rf "${DIR}"' EXIT
  ${HOST} issue view "${ISSUE}" > "${DIR}/issue.json"

  mission="$(cat "${REPO}/MISSION.md")"
  title="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["title"])' "${DIR}/issue.json")"
  body="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("body") or "")' "${DIR}/issue.json")"
  cmts="$(python3 - "${DIR}/issue.json" <<'PYC'
import json, sys
d = json.load(open(sys.argv[1]))
cs = d.get("comments") or []
_a = lambda c: c["author"]["login"] if isinstance(c.get("author"), dict) else (c.get("author") or "")
out = "\n\n".join("[作者: %s]\n%s" % (_a(c), c["body"]) for c in cs[-3:])
print(out if out else "（无评论）")
PYC
)"
  prompt="$(cat "${REPO}/.factory/prompts/triage.md")

——MISSION.md 开始——
${mission}
——MISSION.md 结束——

——issue #${ISSUE} 标题: ${title} 正文开始——
${body}
——正文结束——

——issue 评论开始（最新 3 条；含整改/重投指令时以评论为准）——
${cmts}
——评论结束——"

  t0="$(date +%s)"
  if ! (cd "${REPO}" && omp -p "${prompt}" --no-tools --no-session \
        --config "${REPO}/.factory/omp-isolated.yml" \
        --max-time "$(python3 "${REPO}/.factory/factory_lib.py" timeout triage)") \
      > "${OUT}/${ISSUE}.log" 2>&1; then
    echo "== ${ISSUE}: omp 调用失败（详见 ${OUT}/${ISSUE}.log）" >&2; continue
  fi
  if python3 "${REPO}/.factory/factory_lib.py" parse "${OUT}/${ISSUE}.log" "${OUT}/${ISSUE}.json" accept,reject; then
    v="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "${OUT}/${ISSUE}.json")"
    echo "== ${ISSUE}: verdict=${v}（$(( $(date +%s) - t0 ))s，产物 ${OUT}/${ISSUE}.json）"
  else
    echo "== ${ISSUE}: 裁决输出无法解析（见 ${OUT}/${ISSUE}.log）" >&2
  fi
done
