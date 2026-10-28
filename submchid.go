package wop

import "strings"

// resolveSubMchID 校验并归一化 ISV 子商户身份头 x-wop-sub-mch-id 的值（ISV D-13）：
//  1. trim 前按**原值**逐字符扫描可打印 ASCII（0x20..0x7E）——控制字符（CR/LF/NUL/DEL 等）
//     防头注入，非 ASCII 在 HTTP 头编码下不可靠；
//  2. trim（G2 TrimAll 同集）后为空 → 视为未设置（ok=false，头缺席 = 应用自身身份，AC-20）；
//  3. trim 后含内部空格 → 拒（网关 canonical 的 trimall 会折叠内部空白，而身份查询只做 trim，
//     内部空白破坏签名与身份一一对应）；
//  4. trim 后长度 > 128 字符 → 拒（ASCII 下 len 即字节数）。
//
// 返回 trim 后上行值；ok=false 表示未设置。
func resolveSubMchID(raw string) (resolved string, ok bool, err error) {
	if raw == "" {
		return "", false, nil
	}
	for _, r := range raw {
		if r < 0x20 || r > 0x7e {
			return "", false, newError(CodeConfiguration, "subMchId 须为可打印 ASCII（防头注入/签名歧义）: %d", r)
		}
	}
	trimmed := strings.Trim(raw, requestIDTrimChars)
	if trimmed == "" {
		return "", false, nil
	}
	if strings.ContainsRune(trimmed, ' ') {
		return "", false, newError(CodeConfiguration, "subMchId 不能包含内部空白")
	}
	if len(trimmed) > 128 {
		return "", false, newError(CodeConfiguration, "subMchId 长度不能超过 128（实际 %d）", len(trimmed))
	}
	return trimmed, true, nil
}
