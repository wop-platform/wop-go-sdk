#!/usr/bin/env python3
"""docstring_gate.py 单元测试（外部驱动，与内嵌 --self-test 负控制互补）。

覆盖契约面：符号判定（顶层 func/type/var/const、导出方法、括号分组块）、
docstring 归属判定（//、块注释、空行间隔、组注释不覆盖）、阈值边界
（对外 100%、内部 80% 含等于边界与空集）、扫描面（git ls-files 枚举与
排除、fail-closed）、CLI（无参/--json/--self-test/错误参数、exit 码域）。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import docstring_gate as gate


# ── Symbol / Report 数据结构与双口径划分 ───────────────────────────


def test_symbol_default_has_doc_false():
    s = gate.Symbol("a.go", 1, "Foo", True)
    assert (s.path, s.line, s.name, s.exported, s.has_doc) == \
        ("a.go", 1, "Foo", True, False)


def test_report_partitions_external_internal_and_missing():
    syms = [
        gate.Symbol("a.go", 1, "ExpMissing", True),
        gate.Symbol("a.go", 2, "ExpOk", True, True),
        gate.Symbol("a.go", 3, "intMissing", False),
        gate.Symbol("a.go", 4, "intOk", False, True),
    ]
    r = gate.Report(syms)
    assert [s.name for s in r.external] == ["ExpMissing", "ExpOk"]
    assert [s.name for s in r.internal] == ["intMissing", "intOk"]
    assert [s.name for s in r.missing_external] == ["ExpMissing"]
    assert [s.name for s in r.missing_internal] == ["intMissing"]


def test_report_empty_collections():
    r = gate.Report()
    assert r.symbols == []
    assert r.external == [] and r.internal == []
    assert r.missing_external == [] and r.missing_internal == []


# ── 注释行与 docstring 归属判定 ───────────────────────────────────


@pytest.mark.parametrize("line,expected", [
    ("// 行注释", True),
    ("  // 缩进行注释", True),
    ("/* 块注释开头", True),
    ("  /* 缩进块注释 */", True),
    ("* 块注释续行", True),
    (" */ 块注释结尾行", True),
    ("func F() {}", False),
    ("", False),
])
def test_is_comment_line(line, expected):
    assert gate.is_comment_line(line) is expected


def test_has_doc_first_line_has_no_prev():
    assert gate.has_doc(["func F() {}"], 0) is False


def test_has_doc_blank_line_between_comment_and_decl():
    lines = ["// doc", "", "func F() {}"]
    assert gate.has_doc(lines, 2) is False


def test_has_doc_adjacent_comment_counts():
    assert gate.has_doc(["// doc", "func F() {}"], 1) is True
    assert gate.has_doc(["/* block", " */", "func F() {}"], 2) is True


def test_has_doc_adjacent_code_line_does_not_count():
    assert gate.has_doc(["x := 1", "func F() {}"], 1) is False


# ── scan_text：顶层 func 与方法 ───────────────────────────────────


def test_scan_text_top_level_funcs():
    text = """package wop

// Exported 有 doc。
func Exported() {}

func unexported() {}

func NoDoc() {}
"""
    syms = gate.scan_text("f.go", text)
    assert [(s.name, s.exported, s.has_doc, s.line) for s in syms] == [
        ("Exported", True, True, 4),
        ("unexported", False, False, 6),
        ("NoDoc", True, False, 8),
    ]


def test_scan_text_first_line_func_no_doc():
    syms = gate.scan_text("z.go", "func Z() {}")
    assert [(s.name, s.exported, s.has_doc, s.line) for s in syms] == \
        [("Z", True, False, 1)]


def test_scan_text_methods_only_exported_counted():
    text = """package wop

// Send doc.
func (c *Client) Send() {}

func (c *Client) Hide() {}

// 小写方法不计任何口径（契约内部口径仅顶层）。
func (c *Client) quiet() {}
"""
    syms = gate.scan_text("m.go", text)
    assert [(s.name, s.exported, s.has_doc) for s in syms] == [
        ("Send", True, True),
        ("Hide", True, False),
    ]


def test_scan_text_unclosed_receiver_skips_line():
    assert gate.scan_text("u.go", "func (broken\nfunc Ok() {}\n") == \
        [("z" if False else syms) for syms in []] or \
        gate.scan_text("u.go", "func (broken\nfunc Ok() {}\n")


def test_scan_text_func_invalid_name_skipped():
    assert gate.scan_text("b.go", "func 1bad() {}") == []


def test_scan_text_method_invalid_name_skipped():
    assert gate.scan_text("m.go", "func (c *C) 9bad() {}") == []


def test_scan_text_unclosed_receiver_skips_line():
    syms = gate.scan_text("u.go", "func (broken\nfunc Ok() {}\n")
    # 接收者括号未闭合的行安全跳过，不吞掉后续声明
    assert [(s.name, s.has_doc, s.line) for s in syms] == [("Ok", False, 2)]
def test_scan_text_group_var_block_min_indent_specs():
    text = """package wop

var (
\t// Exp 导出规格有 doc。
\tExp = 1
\tinternal2 = 2
)
"""
    syms = gate.scan_text("g.go", text)
    assert [(s.name, s.exported, s.has_doc, s.line) for s in syms] == [
        ("Exp", True, True, 5),
        ("internal2", False, False, 6),
    ]


def test_scan_text_group_deeper_indent_and_invalid_specs_excluded():
    text = """package wop

const (
\tA = 1
\tdeep = map[string]int{
\t\t"x": 1,
\t}
\t9invalid = 2
)
"""
    syms = gate.scan_text("d.go", text)
    # 最小缩进层规格 A/deep 计入；"x" 更深层不计；9invalid 非法名不计
    assert [(s.name, s.has_doc, s.line) for s in syms] == [
        ("A", False, 4),
        ("deep", False, 5),
    ]


def test_scan_text_group_skips_blank_and_comment_lines():
    text = """package wop

type (
\t// 组注释不覆盖后续规格
\tT struct {
\t\tF int
\t}

\tU int
)
"""
    syms = gate.scan_text("t.go", text)
    # T 紧邻组注释=有 doc；U 前是空行=无 doc；字段 F 与 } 不计
    assert [(s.name, s.exported, s.has_doc, s.line) for s in syms] == [
        ("T", True, True, 5),
        ("U", True, False, 9),
    ]


def test_scan_text_unterminated_group_runs_to_eof():
    syms = gate.scan_text("u.go", "const (\n\tX = 1\n")
    assert [(s.name, s.line) for s in syms] == [("X", 2)]


# ── scan_text：type/var/const 单声明 ─────────────────────────────


def test_scan_text_single_declarations():
    text = """package wop

// Doced 类型说明。
type Doced struct{ F int }

var v = 1

// E 常量说明。
const E = 2
"""
    syms = gate.scan_text("s.go", text)
    assert [(s.name, s.exported, s.has_doc, s.line) for s in syms] == [
        ("Doced", True, True, 4),
        ("v", False, False, 6),
        ("E", True, True, 9),
    ]


def test_scan_text_single_decl_invalid_name_skipped():
    assert gate.scan_text("s.go", "type (x int\nvar 9bad\n") == []


# ── go_files：git ls-files 扫描面与 fail-closed ───────────────────


def _fake_git(stdout: str, returncode: int = 0):
    def fake(cmd, **kwargs):
        if returncode != 0:
            raise subprocess.CalledProcessError(returncode, cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, "")
    return fake


def test_go_files_filter_rules(monkeypatch):
    out = "\n".join([
        "client.go",
        "",                        # 空行跳过
        "client_test.go",          # _test.go 跳过
        "tests/helper.go",         # tests/ 段排除
        "sub/tests/x.go",          # 嵌套 tests/ 段排除
        "examples/demo/main.go",
        "testdata/golden.go",
        "vendor/lib/lib.go",
        "testdata.go",             # 根级同名文件：仅目录段参与排除
        "a.go",
    ])
    monkeypatch.setattr(gate.subprocess, "run", _fake_git(out))
    assert gate.go_files() == ["a.go", "client.go", "testdata.go"]


def test_go_files_empty_output(monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run", _fake_git(""))
    assert gate.go_files() == []


def test_go_files_git_failure_fail_closed(monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run", _fake_git("", returncode=128))
    with pytest.raises(subprocess.CalledProcessError):
        gate.go_files()


# ── verdict 阈值边界 ─────────────────────────────────────────────


def _ext(has_doc=True):
    return gate.Symbol("a.go", 1, "Ext", True, has_doc)


def _int(has_doc=True, line=2):
    return gate.Symbol("a.go", line, "in", False, has_doc)


def test_verdict_missing_external_fails():
    assert gate.verdict(gate.Report([_ext(False), _ext(True)])) is False


def test_verdict_empty_internal_passes():
    assert gate.verdict(gate.Report([_ext(True)])) is True


def test_verdict_internal_exactly_80_percent_passes():
    # 5 内部缺 1 = 恰 80%（契约 ≥80%；判定为 缺失占比 > 0.2 才失败）
    syms = [_ext(True)] + [_int(i != 1, line=i + 1) for i in range(5)]
    assert gate.verdict(gate.Report(syms)) is True


def test_verdict_internal_75_percent_fails():
    # 4 内部缺 1 = 75% < 80%
    syms = [_ext(True)] + [_int(i != 1, line=i + 1) for i in range(4)]
    assert gate.verdict(gate.Report(syms)) is False


def test_verdict_all_documented_passes():
    syms = [_ext(True), _int(True)]
    assert gate.verdict(gate.Report(syms)) is True


# ── 输出格式化 ───────────────────────────────────────────────────


def test_format_missing_lists_external_then_internal():
    r = gate.Report([
        gate.Symbol("e.go", 3, "Ext", True, False),
        gate.Symbol("i.go", 7, "in", False, False),
    ])
    assert gate.format_missing(r) == [
        "e.go:3 Ext（对外，缺 docstring）",
        "i.go:7 in（内部，缺 docstring）",
    ]


def test_format_missing_empty_report():
    assert gate.format_missing(gate.Report()) == []


def test_format_stats_empty_internal():
    r = gate.Report([_ext(True)])
    assert gate.format_stats(r) == "统计: 对外 1/1（100% 要求）、内部 0/0（空集=达标）"


def test_format_stats_with_internal_percentage():
    r = gate.Report([_ext(True), _int(True), _int(False, line=3)])
    stats = gate.format_stats(r)
    assert "对外 1/1（100% 要求）" in stats
    assert "内部 1/2（50%）" in stats


# ── check：多源聚合 ──────────────────────────────────────────────


def test_check_aggregates_sources_in_order():
    r = gate.check([
        ("a.go", "// d\nfunc A() {}"),
        ("b.go", "func b() {}"),
    ])
    assert [(s.path, s.name, s.exported, s.has_doc) for s in r.symbols] == [
        ("a.go", "A", True, True),
        ("b.go", "b", False, False),
    ]


# ── self_test 负控制 ─────────────────────────────────────────────


def test_self_test_embedded_negative_controls_pass(capsys):
    assert gate.self_test() == 0
    assert "4/4" in capsys.readouterr().out



def test_self_test_failure_path_reports_and_returns_one(monkeypatch, capsys):
    real_verdict = gate.verdict
    monkeypatch.setattr(gate, "verdict",
                        lambda report: not real_verdict(report))
    assert gate.self_test() == 1
    err = capsys.readouterr().err
    assert "SELF-TEST FAIL:" in err
    assert "期望 未达标(非零)，实际 达标" in err
    assert "期望 达标，实际 未达标" in err

# ── main CLI ─────────────────────────────────────────────────────

GOOD_FILE = """package wop

// Doced doc.
func Doced() {}
"""

BAD_FILE = """package wop

func NoDoc() {}
"""


@pytest.fixture
def repo(monkeypatch, tmp_path):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    return tmp_path


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py", *argv])
    return gate.main()


def test_main_no_args_pass_exit_zero(repo, monkeypatch, capsys):
    (repo / "good.go").write_text(GOOD_FILE, encoding="utf-8")
    monkeypatch.setattr(gate, "go_files", lambda: ["good.go"])
    assert _run_main(monkeypatch, []) == 0
    out = capsys.readouterr().out
    assert "GATE: docstring 门达标" in out
    assert "统计: 对外 1/1（100% 要求）、内部 0/0（空集=达标）" in out


def test_main_no_args_fail_exit_one(repo, monkeypatch, capsys):
    (repo / "bad.go").write_text(BAD_FILE, encoding="utf-8")
    monkeypatch.setattr(gate, "go_files", lambda: ["bad.go"])
    assert _run_main(monkeypatch, []) == 1
    out = capsys.readouterr().out
    assert "bad.go:3 NoDoc（对外，缺 docstring）" in out
    assert "统计: 对外 0/1（100% 要求）、内部 0/0（空集=达标）" in out
    assert "GATE: docstring 门未达标（对外须 100%、内部须 ≥80%）" in out


def test_main_json_pass_exit_zero(repo, monkeypatch, capsys):
    (repo / "good.go").write_text(GOOD_FILE, encoding="utf-8")
    monkeypatch.setattr(gate, "go_files", lambda: ["good.go"])
    assert _run_main(monkeypatch, ["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "pass": True,
        "external": {"total": 1, "documented": 1},
        "internal": {"total": 0, "documented": 0},
        "missing": [],
    }


def test_main_json_fail_exit_one(repo, monkeypatch, capsys):
    (repo / "bad.go").write_text(BAD_FILE, encoding="utf-8")
    monkeypatch.setattr(gate, "go_files", lambda: ["bad.go"])
    assert _run_main(monkeypatch, ["--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["pass"] is False
    assert data["missing"] == [
        {"path": "bad.go", "line": 3, "name": "NoDoc", "exported": True}]


def test_main_self_test_flag_zero(monkeypatch, capsys):
    assert _run_main(monkeypatch, ["--self-test"]) == 0
    assert "4/4" in capsys.readouterr().out


def test_main_unknown_arg_rejected(monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, ["--nope"])
    assert exc.value.code == 2
