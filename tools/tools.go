//go:build tools

// Package tools 以 build tag 隔离的方式钉住仓库所需的开发期工具依赖，
// 使其进入 go.mod / go.sum 供 `go run` 复现，但绝不参与正常运行时构建。
// 运行时依赖白名单（见 CONTRIBUTING §2 与 ci.yml 依赖白名单步骤）不受影响：
// CI 白名单检查的是 `go list -deps .`，本文件因 build tag 被排除在外。
package tools

import (
	// apidiff：公共 API 快照门禁（internal/api/api.golden 的生成器）。
	_ "golang.org/x/exp/cmd/apidiff"
)
