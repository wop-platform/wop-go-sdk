// Package goldmarkfloor 以空导入承托 go.mod 中 goldmark v1.8.6 的 require 行：
// CVE-2026-5160（renderer/html XSS）——x/tools@v0.49.0 的模块图边钉 v1.4.13，
// 而 replace 对下游模块图无效，必须以本模块 require 参与下游 MVS 选择。
// 空导入放在 internal（tools/tools.go 之外）：白名单门禁（go list -deps .）
// 只看根包，internal 子包不入图；tidy 则因主模块包导入而保留 require。
// x/tools 抬高 goldmark 要求后整包删除。
package goldmarkfloor

import _ "github.com/yuin/goldmark"
