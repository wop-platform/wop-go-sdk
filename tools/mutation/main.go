// Command mutation 是 wop-go-sdk 的变异测试引擎（PIT 不可用于 Go，本仓自研）。
//
// 用法（在仓库根目录）:
//
//	go run ./tools/mutation -out /tmp/mutation-report.json [-only file.go:line] [-parallel 4]
//
// 流程：基线测试确认绿 → AST 扫描根目录源文件收集变异点 → 复制 module 到
// 各 worker 独立副本 → 逐变异体单点重写副本文件 → 副本内 go test ./... → 分类：
//
//	killed   测试失败（含超时：行为已变且被捕获）
//	invalid  编译失败（无效变异体，不计入击杀率分母）
//	survived 测试全绿（变异存活，测试盲区）
//
// 击杀率 = killed / (killed + survived)。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type status string

const (
	statusKilled   status = "killed"
	statusSurvived status = "survived"
	statusInvalid  status = "invalid"
)

// operator 变异算子（13 类实现，覆盖条件/数学/返回值/常量）。
type operator string

const (
	opROR  operator = "ROR"  // 关系算子取反 (== <-> !=)
	opOBB  operator = "OBB"  // 条件边界 (< <-> <=, > <-> >=)
	opLOR  operator = "LOR"  // 逻辑连接词 (&& <-> ||)
	opAOR  operator = "AOR"  // 算术 (+ <-> -, * <-> /)
	opOKN  operator = "OKN"  // 整数常量 (n -> n+1)
	opROI  operator = "ROI"  // 布尔字面量翻转 (true <-> false)
	opCOI  operator = "COI"  // 条件真值注入 (if cond -> if true/false)
	opSDEL operator = "SDEL" // 语句删除
	opIDM  operator = "IDM"  // 自增自减翻转 (++ <-> --)
	opSBR  operator = "SBR"  // 移位方向翻转 (<< <-> >>)
	opUOI  operator = "UOI"  // 一元负号删除 (-x -> x)
	opLCR  operator = "LCR"  // 字符串字面量变异
	opBRK  operator = "BRK"  // break <-> continue
)

var operatorNames = map[operator]string{
	opROR:  "关系算子取反",
	opOBB:  "条件边界替换",
	opLOR:  "逻辑连接词替换",
	opAOR:  "算术运算符替换",
	opOKN:  "整数常量增量",
	opROI:  "布尔字面量翻转",
	opCOI:  "条件真值注入",
	opSDEL: "语句删除",
	opIDM:  "自增自减翻转",
	opSBR:  "移位方向翻转",
	opUOI:  "一元负号删除",
	opLCR:  "字符串字面量变异",
	opBRK:  "break/continue 交换",
}

type mutant struct {
	Operator operator `json:"op"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Col      int      `json:"col"`
	Desc     string   `json:"desc"`
	Status   status   `json:"status"`
	// Diag 为真表示该变异点位于错误构造调用（newError/fuzzyError/
	// errors.New/fmt.Errorf）的参数内：诊断文案非对外契约（I7），其
	// LCR 变异不计入击杀率分母（口径B）。
	Diag bool `json:"diag,omitempty"`
}

// mutationSite 单点变异：match 判定容器/目标节点，apply 原地改写。
type mutationSite struct {
	op        operator
	file      string
	pos       token.Pos // 报告定位（目标构造处）
	line, col int
	desc      string
	diag      bool // 位于错误构造调用参数内（诊断文案位置）
	match     func(ast.Node) bool
	apply     func(ast.Node) bool
}

func main() {
	var (
		outPath   = flag.String("out", "mutation-report.json", "报告输出路径")
		only      = flag.String("only", "", "仅跑指定文件:行（调试用，如 suite.go:63）")
		onlyFiles = flag.String("only-files", "", "仅跑指定文件（逗号分隔，增量/CI 用，如 suite.go,keys.go）")
		par       = flag.Int("parallel", 4, "并行 worker 数（各持独立副本）")
		timeout   = flag.Duration("timeout", 180*time.Second, "单变异体测试超时")
		gateB     = flag.Float64("gate-b", 0, "口径B 击杀率门禁（0-1，如 0.80；0=不启用）。口径B 分母剔除错误构造参数内字符串（诊断文案，非契约）的存活变异")
		keepWork  = flag.Bool("keep-work", false, "保留工作副本（调试）")
	)
	flag.Parse()

	root, err := filepath.Abs(".")
	must(err, "定位仓库根")

	// 0. 基线：当前工作树测试必须全绿（任何 worker 开始前完成）
	fmt.Println("基线测试运行中…")
	if pass, out := runTests(root, 3*time.Minute); !pass {
		log.Fatalf("基线测试不绿，中止:\n%s", tailN(out, 30))
	}
	fmt.Println("基线绿 ✓")

	// 1. 收集源文件与变异点
	files, sites, err := collectSites(root)
	must(err, "扫描变异点")
	fmt.Printf("源文件 %d 个，变异点 %d 个\n", len(files), len(sites))

	if *only != "" {
		sites = filterOnly(sites, *only)
		fmt.Printf("only 过滤后 %d 个\n", len(sites))
	}
	if *onlyFiles != "" {
		sites = filterOnlyFiles(sites, strings.Split(*onlyFiles, ","))
		fmt.Printf("only-files 过滤后 %d 个\n", len(sites))
	}
	if len(sites) == 0 {
		fmt.Println("无变异点，跳过")
		return
	}

	// 2. 并发 worker：每 worker 独立副本
	var wg sync.WaitGroup
	jobs := make(chan int)
	results := make([]mutant, len(sites))
	var progress int
	var mu sync.Mutex

	for w := 0; w < *par; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			work := filepath.Join(os.TempDir(), fmt.Sprintf("wop-mut-w%d-%d", worker, time.Now().UnixNano()))
			must(copyModule(root, work), fmt.Sprintf("worker %d 建副本", worker))
			defer func() {
				if !*keepWork {
					os.RemoveAll(work)
				}
			}()
			for idx := range jobs {
				s := sites[idx]
				mu.Lock()
				src, err := os.ReadFile(filepath.Join(root, s.file))
				mu.Unlock()
				if err != nil {
					log.Fatalf("读源文件: %v", err)
				}
				m := mutant{Operator: s.op, File: s.file, Line: s.line, Col: s.col, Desc: s.desc, Diag: s.diag}
				mutated, err := applyToFile(src, s)
				if err != nil {
					m.Status = statusInvalid
				} else {
					target := filepath.Join(work, s.file)
					_ = os.WriteFile(target, mutated, 0o644)
					pass, out := runTests(work, *timeout)
					m.Status = classify(pass, out)
					_ = os.WriteFile(target, src, 0o644)
				}
				mu.Lock()
				results[idx] = m
				progress++
				if progress%50 == 0 {
					fmt.Printf("  进度 %d/%d\n", progress, len(sites))
				}
				mu.Unlock()
			}
		}(w)
	}
	for i := range sites {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if failed := report(results, *outPath, *gateB); failed {
		os.Exit(1)
	}
}

// ---------- 变异点收集 ----------

func collectSites(root string) ([]string, []mutationSite, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	var sites []mutationSite
	for _, f := range files {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			return nil, nil, err
		}
		fset := token.NewFileSet()
		astFile, err := parser.ParseFile(fset, f, src, parser.ParseComments)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, s := range fileSites(astFile, fset) {
			s.file = f
			sites = append(sites, s)
		}
	}
	return files, sites, nil
}

func fileSites(f *ast.File, fset *token.FileSet) []mutationSite {
	var out []mutationSite
	posOf := func(p token.Pos) (int, int) {
		pos := fset.Position(p)
		return pos.Line, pos.Column
	}
	diagPos := diagnosticStringPositions(f)
	add := func(p token.Pos, op operator, desc string,
		match func(ast.Node) bool, apply func(ast.Node) bool) {
		line, col := posOf(p)
		_, isDiag := diagPos[p]
		out = append(out, mutationSite{
			op: op, pos: p, line: line, col: col, desc: desc, diag: isDiag,
			match: match, apply: apply,
		})
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			swap := func(from, to token.Token, op operator) {
				add(node.OpPos, op, fmt.Sprintf("%s → %s", from, to),
					func(m ast.Node) bool {
						b, ok := m.(*ast.BinaryExpr)
						return ok && b.OpPos == node.OpPos && b.Op == from
					},
					func(m ast.Node) bool {
						m.(*ast.BinaryExpr).Op = to
						return true
					})
			}
			switch node.Op {
			case token.EQL:
				swap(token.EQL, token.NEQ, opROR)
			case token.NEQ:
				swap(token.NEQ, token.EQL, opROR)
			case token.LSS:
				swap(token.LSS, token.LEQ, opOBB)
			case token.LEQ:
				swap(token.LEQ, token.LSS, opOBB)
			case token.GTR:
				swap(token.GTR, token.GEQ, opOBB)
			case token.GEQ:
				swap(token.GEQ, token.GTR, opOBB)
			case token.LAND:
				swap(token.LAND, token.LOR, opLOR)
			case token.LOR:
				swap(token.LOR, token.LAND, opLOR)
			case token.ADD:
				swap(token.ADD, token.SUB, opAOR)
			case token.SUB:
				swap(token.SUB, token.ADD, opAOR)
			case token.MUL:
				swap(token.MUL, token.QUO, opAOR)
			case token.SHL:
				swap(token.SHL, token.SHR, opSBR)
			case token.SHR:
				swap(token.SHR, token.SHL, opSBR)
			}

		case *ast.BasicLit:
			switch {
			case node.Kind == token.INT:
				if _, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
					old := node.Value
					newVal := strconv.FormatInt(mustInt(old)+1, 10)
					add(node.Pos(), opOKN, old+" → "+newVal,
						func(m ast.Node) bool {
							l, ok := m.(*ast.BasicLit)
							return ok && l.Pos() == node.Pos() && l.Kind == token.INT
						},
						func(m ast.Node) bool {
							m.(*ast.BasicLit).Value = newVal
							return true
						})
				}
			case node.Kind == token.STRING:
				newVal := strings.TrimSuffix(node.Value, `"`) + `mut"`
				add(node.Pos(), opLCR, "字符串加后缀 mut",
					func(m ast.Node) bool {
						l, ok := m.(*ast.BasicLit)
						return ok && l.Pos() == node.Pos() && l.Kind == token.STRING
					},
					func(m ast.Node) bool {
						m.(*ast.BasicLit).Value = newVal
						return true
					})
			}

		case *ast.Ident:
			if node.Name == "true" || node.Name == "false" {
				flipped := map[string]string{"true": "false", "false": "true"}[node.Name]
				add(node.Pos(), opROI, node.Name+" → "+flipped,
					func(m ast.Node) bool {
						i, ok := m.(*ast.Ident)
						return ok && i.Pos() == node.Pos() && (i.Name == "true" || i.Name == "false")
					},
					func(m ast.Node) bool {
						m.(*ast.Ident).Name = flipped
						return true
					})
			}

		case *ast.IfStmt:
			for _, repl := range []string{"true", "false"} {
				repl := repl
				add(node.Pos(), opCOI, "if cond → if "+repl,
					func(m ast.Node) bool {
						i, ok := m.(*ast.IfStmt)
						return ok && i.Pos() == node.Pos()
					},
					func(m ast.Node) bool {
						i := m.(*ast.IfStmt)
						i.Cond = &ast.Ident{NamePos: i.Cond.Pos(), Name: repl}
						return true
					})
			}

		case *ast.BlockStmt:
			for _, stmt := range node.List {
				if _, isExpr := stmt.(*ast.ExprStmt); !isExpr {
					continue
				}
				target := stmt.Pos()
				add(target, opSDEL, "删除表达式语句",
					func(m ast.Node) bool {
						blk, ok := m.(*ast.BlockStmt)
						if !ok {
							return false
						}
						for _, st := range blk.List {
							if st.Pos() == target {
								return true
							}
						}
						return false
					},
					func(m ast.Node) bool {
						blk := m.(*ast.BlockStmt)
						for j, st := range blk.List {
							if st.Pos() == target {
								blk.List = append(blk.List[:j], blk.List[j+1:]...)
								return true
							}
						}
						return false
					})
			}

		case *ast.IncDecStmt:
			old := node.Tok
			flipped := token.ADD
			if node.Tok == token.ADD {
				flipped = token.SUB
			}
			add(node.TokPos, opIDM, old.String()+" → "+flipped.String(),
				func(m ast.Node) bool {
					i, ok := m.(*ast.IncDecStmt)
					return ok && i.TokPos == node.TokPos
				},
				func(m ast.Node) bool {
					m.(*ast.IncDecStmt).Tok = flipped
					return true
				})

		case *ast.UnaryExpr:
			if node.Op == token.SUB {
				add(node.OpPos, opUOI, "-x → x",
					func(m ast.Node) bool {
						u, ok := m.(*ast.UnaryExpr)
						return ok && u.OpPos == node.OpPos && u.Op == token.SUB
					},
					func(m ast.Node) bool {
						m.(*ast.UnaryExpr).Op = token.ADD
						return true
					})
			}

		case *ast.BranchStmt:
			if node.Tok == token.BREAK || node.Tok == token.CONTINUE {
				old := node.Tok
				flipped := token.CONTINUE
				if node.Tok == token.CONTINUE {
					flipped = token.BREAK
				}
				add(node.TokPos, opBRK, old.String()+" → "+flipped.String(),
					func(m ast.Node) bool {
						b, ok := m.(*ast.BranchStmt)
						return ok && b.TokPos == node.TokPos
					},
					func(m ast.Node) bool {
						m.(*ast.BranchStmt).Tok = flipped
						return true
					})
			}
		}
		return true
	})
	return out
}

func mustInt(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

// applyToFile 对单文件源码应用单点变异，返回重写后的字节。
func applyToFile(src []byte, s mutationSite) ([]byte, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, s.file, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	applied := false
	ast.Inspect(f, func(n ast.Node) bool {
		if applied || n == nil {
			return false
		}
		if s.match(n) && s.apply(n) {
			applied = true
		}
		return !applied
	})
	if !applied {
		return nil, fmt.Errorf("未命中目标节点")
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, f); err != nil {
		return nil, err
	}
	return gofmt(buf.Bytes())
}

// ---------- 执行与分类 ----------

var buildFailRe = regexp.MustCompile(`\[build failed\]|setup failed|symbol .* declared and not used|undefined:|invalid operation|cannot use|mismatched types|declared and not used`)

func runTests(dir string, timeout time.Duration) (pass bool, output string) {
	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return false, err.Error()
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err == nil, buf.String()
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return false, "MUTATION_TIMEOUT"
	}
}

func classify(pass bool, output string) status {
	if pass {
		return statusSurvived
	}
	if buildFailRe.MatchString(output) {
		return statusInvalid
	}
	return statusKilled
}

// ---------- 报告 ----------

func report(results []mutant, outPath string, gateB float64) bool {
	type agg struct{ k, s, i int }
	byOp := map[operator]*agg{}
	var k, s, i, sDiag int // sDiag：诊断文案位置的存活（口径B 剔除）
	for _, m := range results {
		a, ok := byOp[m.Operator]
		if !ok {
			a = &agg{}
			byOp[m.Operator] = a
		}
		switch m.Status {
		case statusKilled:
			a.k++
			k++
		case statusSurvived:
			a.s++
			s++
			if m.Diag {
				sDiag++
			}
		case statusInvalid:
			a.i++
			i++
		}
	}
	fmt.Println("\n===== 变异测试汇总 =====")
	ops := make([]operator, 0, len(byOp))
	for op := range byOp {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(a, b int) bool { return ops[a] < ops[b] })
	fmt.Printf("%-6s %-16s %7s %9s %8s\n", "算子", "说明", "killed", "survived", "invalid")
	for _, op := range ops {
		a := byOp[op]
		fmt.Printf("%-6s %-16s %7d %9d %8d\n", op, operatorNames[op], a.k, a.s, a.i)
	}
	denA := k + s
	denB := denA - sDiag
	rateA, rateB := 0.0, 0.0
	if denA > 0 {
		rateA = float64(k) / float64(denA) * 100
	}
	if denB > 0 {
		rateB = float64(k) / float64(denB) * 100
	}
	fmt.Printf("\n总计: killed=%d survived=%d(其中诊断文案位 %d) invalid=%d\n", k, s, sDiag, i)
	fmt.Printf("口径A raw 击杀率        = %d/%d = %.1f%%\n", k, denA, rateA)
	fmt.Printf("口径B 剔诊断文案击杀率  = %d/%d = %.1f%%（invalid 不计分母）\n", k, denB, rateB)

	var survivors []mutant
	for _, m := range results {
		if m.Status == statusSurvived {
			survivors = append(survivors, m)
		}
	}
	sort.Slice(survivors, func(a, b int) bool {
		if survivors[a].File != survivors[b].File {
			return survivors[a].File < survivors[b].File
		}
		return survivors[a].Line < survivors[b].Line
	})
	fmt.Printf("\n存活变异体 %d 个:\n", len(survivors))
	for _, m := range survivors {
		fmt.Printf("  %-5s %s:%d:%d  %s\n", m.Operator, m.File, m.Line, m.Col, m.Desc)
	}

	data, err := json.MarshalIndent(results, "", "  ")
	must(err, "序列化报告")
	must(os.WriteFile(outPath, data, 0o644), "写报告")
	fmt.Printf("\n报告已写入 %s\n", outPath)
	if gateB > 0 {
		if denB == 0 {
			fmt.Printf("\n门禁（口径B ≥ %.0f%%）：无有效变异体，门禁跳过\n", gateB*100)
			return false
		}
		if rateB/100 < gateB {
			fmt.Printf("\n门禁失败（口径B %.1f%% < %.1f%%）\n", rateB, gateB*100)
			return true
		}
		fmt.Printf("\n门禁通过（口径B %.1f%% ≥ %.1f%%）\n", rateB, gateB*100)
	}
	return false
}

// diagnosticStringPositions 收集错误构造调用（newError/fuzzyError/errors.New/
// fmt.Errorf）参数区内的全部字符串字面量位置——这些字符串是诊断文案
// （非对外契约，I7），其 LCR 变异按口径B 从分母剔除。
func diagnosticStringPositions(f *ast.File) map[token.Pos]struct{} {
	out := map[token.Pos]struct{}{}
	var callees = map[string]bool{
		"newError": true, "fuzzyError": true,
		"errors.New": true, "fmt.Errorf": true, "Errorf": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || !callees[ident.Name] {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(a ast.Node) bool {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					out[lit.Pos()] = struct{}{}
				}
				return true
			})
		}
		return false
	})
	return out
}

func filterOnlyFiles(sites []mutationSite, names []string) []mutationSite {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[strings.TrimSpace(filepath.Base(n))] = struct{}{}
	}
	var out []mutationSite
	for _, s := range sites {
		if _, ok := set[s.file]; ok {
			out = append(out, s)
		}
	}
	return out
}

// ---------- 基础设施 ----------

func filterOnly(sites []mutationSite, pattern string) []mutationSite {
	filePart, linePart, _ := strings.Cut(pattern, ":")
	var out []mutationSite
	for _, s := range sites {
		if s.file == filePart && (linePart == "" || strconv.Itoa(s.line) == linePart) {
			out = append(out, s)
		}
	}
	return out
}

func copyModule(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "tools":
				if rel != "." {
					return filepath.SkipDir
				}
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, info.Mode())
	})
}

func gofmt(src []byte) ([]byte, error) {
	cmd := exec.Command("gofmt")
	cmd.Stdin = bytes.NewReader(src)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func tailN(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func must(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
