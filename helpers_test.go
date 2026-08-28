package wop

import (
	"bytes"
	"io"
	"testing"
)

// deterministicReader 固定字节流（联调/向量构造用）。
func deterministicReader() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x5A}, 4096)) }

func readBytes(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		t.Fatalf("readBytes(%d): %v", n, err)
	}
	return out
}

func vDekPayloadSM2(t *testing.T) string {
	t.Helper()
	return loadGoldenVectors(t).Inputs.DekPayloadSM2
}
