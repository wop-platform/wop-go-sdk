#!/usr/bin/env python3
"""wop-go-sdk docstring 门检查器（统一契约 2026-08-31）。

度量口径（Go，契约各语言符号定义表）：
  对外（100%）= 大写开头顶层 func/type/var/const + 导出方法（方法名大写开头）；
  内部（≥80%，空集达标）= 小写顶层声明（小写方法不计——契约内部口径仅顶层）。

docstring 判定 = 声明前紧邻注释块：前一非空行以 // 或 /* 开头（块注释
续行 */ 结尾行亦算注释行），且与被查声明之间无空行；标准 // Name ... 算。

扫描面（反作弊）：git ls-files 枚举 *.go（非 glob 全扫），排除 *_test.go
与 tests/、examples/、testdata/、vendor/ 路径段。

CLI 契约：无参 exit 0=达标 / 1=未达标，stdout 逐符号缺失清单
（路径:行号 符号名）+ 统计（对外 x/y、内部 a/b）；--self-test 负控制；
--json 输出 JSON 统计。退出码域 {0,1}（mutations judge 契约）。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# 排除路径段（契约：tests/、示例、生成物；testdata 向量真源非 SDK API 面）
EXCLUDED_PARTS = {"tests", "examples", "testdata", "vendor"}

GROUP_RE = re.compile(r"^(type|var|const)\s*\(\s*$")
SINGLE_RE = re.compile(r"^(?:type|var|const)\s+([A-Za-z_][A-Za-z0-9_]*)")
SPEC_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\b")


@dataclass
class Symbol:
    """一个被查声明（顶层 func/type/var/const 规格或导出方法）。"""

    path: str
    line: int  # 1 基
    name: str
    exported: bool
    has_doc: bool = False


@dataclass
class Report:
    """扫描结果：逐符号缺失清单 + 双口径统计。"""

    symbols: list[Symbol] = field(default_factory=list)

    @property
    def external(self) -> list[Symbol]:
        return [s for s in self.symbols if s.exported]

    @property
    def internal(self) -> list[Symbol]:
        return [s for s in self.symbols if not s.exported]

    @property
    def missing_external(self) -> list[Symbol]:
        return [s for s in self.external if not s.has_doc]

    @property
    def missing_internal(self) -> list[Symbol]:
        return [s for s in self.internal if not s.has_doc]


def is_comment_line(line: str) -> bool:
    """注释行：// 行、/* 开头、块注释续行（* / */ 结尾行）。"""
    t = line.strip()
    return t.startswith("//") or t.startswith("/*") or t.startswith("*")


def has_doc(lines: list[str], idx: int) -> bool:
    """idx（0 基）声明行的 docstring 判定（契约：紧邻注释块、无空行）。"""
    if idx == 0:
        return False
    prev = lines[idx - 1]
    if not prev.strip():
        return False  # 注释块与声明间有空行 → 非紧邻
    return is_comment_line(prev)


def scan_text(path: str, text: str) -> list[Symbol]:
    """解析单个 Go 源文本，产出被查符号清单。

    顶层声明识别：gofmt 下顶层声明恒列 0 起，故以行首关键字判定；
    type/var/const 分组括号块按组内最小缩进层识别规格行（更深层为
    结构体字段/续行，不计）。
    """
    lines = text.split("\n")
    symbols: list[Symbol] = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        if line.startswith("func "):
            rest = line[len("func "):].lstrip()
            is_method = rest.startswith("(")
            if is_method:
                close = rest.find(")")
                if close < 0:
                    i += 1
                    continue
                rest = rest[close + 1:].lstrip()
            m = SPEC_RE.match(rest)
            if m:
                name = m.group(1)
                exported = name[0].isupper()
                # 契约口径：顶层 func 全计（大写=对外/小写=内部）；
                # 方法仅导出方法计对外，小写方法不计任何口径。
                if not is_method or exported:
                    symbols.append(Symbol(path, i + 1, name, exported,
                                          has_doc(lines, i)))
        elif GROUP_RE.match(line):
            # 分组声明（type/var/const 括号块）：最小缩进层 = 规格层
            min_indent: int | None = None
            j = i + 1
            while j < n and lines[j].strip() != ")":
                raw = lines[j]
                if not raw.strip() or is_comment_line(raw):
                    j += 1
                    continue
                indent = len(raw) - len(raw.lstrip())
                if min_indent is None:
                    min_indent = indent
                if indent == min_indent:
                    m = SPEC_RE.match(raw.lstrip())
                    if m:
                        name = m.group(1)
                        symbols.append(Symbol(path, j + 1, name,
                                              name[0].isupper(),
                                              has_doc(lines, j)))
                j += 1
            i = j
            continue
        elif line.startswith(("type ", "var ", "const ")):
            m = SINGLE_RE.match(line)
            if m:
                name = m.group(1)
                symbols.append(Symbol(path, i + 1, name, name[0].isupper(),
                                      has_doc(lines, i)))
        i += 1
    return symbols


def go_files() -> list[str]:
    """扫描面：git ls-files 枚举 + 排除规则（契约反作弊条款）。"""
    out = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "*.go"],
        capture_output=True, text=True, check=True,
    ).stdout
    files = []
    for rel in out.splitlines():
        if not rel or rel.endswith("_test.go"):
            continue
        parts = Path(rel).parts
        if any(p in EXCLUDED_PARTS for p in parts[:-1]):
            continue
        files.append(rel)
    return sorted(files)


def verdict(report: Report) -> bool:
    """对外 100% + 内部 ≥80%（空内部集 = 达标）。"""
    if report.missing_external:
        return False
    total = len(report.internal)
    if total and len(report.missing_internal) / total > 0.2:
        return False
    return True


def format_missing(report: Report) -> list[str]:
    out = []
    for s in report.missing_external:
        out.append(f"{s.path}:{s.line} {s.name}（对外，缺 docstring）")
    for s in report.missing_internal:
        out.append(f"{s.path}:{s.line} {s.name}（内部，缺 docstring）")
    return out


def format_stats(report: Report) -> str:
    ext, internal = report.external, report.internal
    ext_ok = len(ext) - len(report.missing_external)
    int_ok = len(internal) - len(report.missing_internal)
    return (f"统计: 对外 {ext_ok}/{len(ext)}（100% 要求）、"
            f"内部 {int_ok}/{len(internal)}"
            + (f"（{int_ok / len(internal):.0%}）" if internal
               else "（空集=达标）"))


def check(sources: list[tuple[str, str]]) -> Report:
    """核心检查：[(路径, 文本)] → Report（main 与 --self-test 共用路径）。"""
    report = Report()
    for path, text in sources:
        report.symbols.extend(scan_text(path, text))
    return report


# ── --self-test 负控制（契约：内嵌已知坏输入，断言检查逻辑非零）─────────

BAD_EXPORTED_FUNC = """package wop

func MissingDoc() {}
"""

BAD_GROUP_CONST = """package wop

// 组注释不覆盖组内规格（契约：规格前一非空行须为注释行）。
const (
\tExportedInGroup = "v"
)
"""

BAD_INTERNAL_RATIO = """package wop

// Ok 内部达标样本。
func ok() {}

func noDoc1() {}
func noDoc2() {}
"""

GOOD_SNIPPET = """package wop

// Documented 导出函数有 doc。
func Documented() {}

const (
\t// Grouped 组内规格逐符号有 doc。
\tGrouped = "v"
)
"""


def self_test() -> int:
    """负控制：坏输入必须判未达标（exit 1 语义），好输入必须判达标。"""
    failures = []
    cases = [
        ("导出函数缺 doc", [("<self-test>/bad.go", BAD_EXPORTED_FUNC)], False),
        ("分组 const 规格缺逐符号 doc", [("<self-test>/group.go", BAD_GROUP_CONST)], False),
        ("内部覆盖率跌破 80%", [("<self-test>/internal.go", BAD_INTERNAL_RATIO)], False),
        ("全有 doc 好样本", [("<self-test>/good.go", GOOD_SNIPPET)], True),
    ]
    for label, sources, expect_pass in cases:
        got_pass = verdict(check(sources))
        if got_pass != expect_pass:
            failures.append(
                f"{label}: 期望 {'达标' if expect_pass else '未达标(非零)'}，"
                f"实际 {'达标' if got_pass else '未达标'}")
    if failures:
        print("SELF-TEST FAIL:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("self-test: 4/4 用例通过（负控制有效）")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="负控制测试（内嵌已知坏输入断言非零）")
    parser.add_argument("--json", action="store_true",
                        help="输出 JSON 统计")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    sources = [(rel, (REPO_ROOT / rel).read_text(encoding="utf-8"))
               for rel in go_files()]
    report = check(sources)

    if args.json:
        print(json.dumps({
            "pass": verdict(report),
            "external": {"total": len(report.external),
                         "documented": len(report.external) - len(report.missing_external)},
            "internal": {"total": len(report.internal),
                         "documented": len(report.internal) - len(report.missing_internal)},
            "missing": [{"path": s.path, "line": s.line, "name": s.name,
                         "exported": s.exported}
                        for s in report.missing_external + report.missing_internal],
        }, ensure_ascii=False, indent=2))
        return 0 if verdict(report) else 1

    for line in format_missing(report):
        print(line)
    print(format_stats(report))
    if not verdict(report):
        print("GATE: docstring 门未达标（对外须 100%、内部须 ≥80%）")
        return 1
    print("GATE: docstring 门达标")
    return 0


if __name__ == "__main__":
    sys.exit(main())
