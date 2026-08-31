package wop

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// 线上编码契约（spec §3.4 / D10）：二进制一律 base64url 无填充，
// 严格模式拒收 '=' 与标准字母表字符；十六进制统一小写。

// b64urlEncoder 线上 base64url 无填充编码器（D10 单例，严格字母表由解码侧强制）。
var b64urlEncoder = base64.RawURLEncoding

// EncodeB64URL 编码为 base64url 无填充。
func EncodeB64URL(b []byte) string {
	return b64urlEncoder.EncodeToString(b)
}

// DecodeB64URL 严格解码 base64url 无填充：含 '='、'+'、'/'、空白或
// 长度非法（%4==1）一律拒绝（F6/F7 负向量锚点）。
func DecodeB64URL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/ \t\r\n") {
		return nil, newError(CodeProtocol, "base64url 串含非法字符（须无填充、URL 字母表）")
	}
	b, err := b64urlEncoder.Strict().DecodeString(s)
	if err != nil {
		return nil, newError(CodeProtocol, "base64url 解码失败：%v", err)
	}
	return b, nil
}

// LowerHex 小写十六进制（D10：统一小写，.NET BitConverter 大写为经典翻车点）。
func LowerHex(b []byte) string {
	return hex.EncodeToString(b)
}

// TrimAll：去首尾空白，连续空白折叠为单个空格（canonicalRequest 用）。
// 空白类对齐 Java Character.isWhitespace 常见子集：空格、\t、\n、\x0B、\f、\r。
func TrimAll(s string) string {
	s = strings.Trim(s, " \t\n\x0B\f\r")
	for strings.Contains(s, "  ") ||
		strings.ContainsAny(s, "\t\n\x0B\f\r") {
		s = collapseWhitespace(s)
	}
	return s
}

// collapseWhitespace 单趟折叠：连续空白（空格/\t/\n/\x0B/\f/\r）压成单个空格。
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\x0B' || c == '\f' || c == '\r' {
			if !prevSpace {
				b.WriteByte(' ')
			}
			prevSpace = true
		} else {
			b.WriteByte(c)
			prevSpace = false
		}
	}
	return b.String()
}

// URLEncodeJava 按 java.net.URLEncoder(UTF-8) 语义编码，并将输出中的
// '+' 替换回 %20（canonicalRequest 的 RFC 3986 风格钉子，F2）：
// 保留 [A-Za-z0-9.-*_]，其余字符按 UTF-8 字节 %XX，空格 → %20。
func URLEncodeJava(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '*' || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteString(hexUpperTable[c])
		}
	}
	return b.String()
}

// hexUpperTable 字节 → 两位大写 hex 查表（URLEncodeJava 的 %XX 直出，零分配）。
var hexUpperTable = [256]string{
	"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
	"10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
	"20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
	"30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
	"40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
	"50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
	"60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
	"70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
	"80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
	"90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
	"A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
	"B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
	"C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
	"D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
	"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
	"F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF",
}
