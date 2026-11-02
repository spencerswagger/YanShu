package httpapi

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spencerswagger/YanShu/server/internal/auth"
)

var errBadB64 = errors.New("invalid base64url")

// decodeB64 解 base64url（无填充）。带 `=` 或长度 %4==1 一律拒绝，
// 与 CRYPTO-PACK §3.2 的外部编码约定一致。
func decodeB64(s string) ([]byte, error) {
	if strings.ContainsRune(s, '=') || len(s)%4 == 1 {
		return nil, errBadB64
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errBadB64
	}
	return b, nil
}

// decodePubKey 校验并解码未压缩 SM2 公钥（0x04 ‖ X32 ‖ Y32）。
//
// 这里只做**形状**校验（长度与前缀）；点是否在曲线上由验签实现负责——
// 服务端不实现 SM2 曲线运算，就不在这里假装校验过。
func decodePubKey(s string) ([]byte, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 65 || b[0] != 0x04 {
		return nil, errors.New("public key must be 65-byte uncompressed point")
	}
	return b, nil
}

// sanitizeNickname 归一化昵称：NFC 不入库（依赖客户端）、去首尾空白、
// 拒绝控制字符、限制 1..64 字节。
//
// 昵称是服务端**唯一**存储的用户自由文本，所以这里卡得比较紧：
// 不允许换行/控制字符，避免日志注入与奇怪的渲染。
func sanitizeNickname(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) {
		return "", errors.New("nickname must be non-empty valid UTF-8")
	}
	if len(s) > 64 {
		return "", errors.New("nickname must be at most 64 bytes")
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			return "", errors.New("nickname must not contain control characters")
		}
	}
	return s, nil
}

// chunkPlaintextLen 返回第 index 块的明文长度（CRYPTO-PACK §4.2）。
func chunkPlaintextLen(chunkSize uint32, plaintextSize uint64, chunkCount, index uint32) uint32 {
	if chunkCount == 0 || index >= chunkCount {
		return 0
	}
	if index < chunkCount-1 {
		return chunkSize
	}
	used := uint64(chunkSize) * uint64(chunkCount-1)
	if plaintextSize <= used {
		return 0
	}
	return uint32(plaintextSize - used)
}

// expectedChunkCTLen 是传输切片长度 = 明文块长 + 16 字节 GCM tag（§6.3）。
func expectedChunkCTLen(chunkSize uint32, plaintextSize uint64, chunkCount, index uint32) uint32 {
	return chunkPlaintextLen(chunkSize, plaintextSize, chunkCount, index) + 16
}

// expectedChunkCount 由明文总长与块大小推出块数；空文件也有 1 块（§4.2）。
func expectedChunkCount(plaintextSize uint64, chunkSize uint32) uint32 {
	if chunkSize == 0 {
		return 0
	}
	if plaintextSize == 0 {
		return 1
	}
	return uint32((plaintextSize + uint64(chunkSize) - 1) / uint64(chunkSize))
}

// buildBitmap 生成「已收块」位图：bit i 对应块 i（LSB 序）。
func buildBitmap(indexes []int, count uint32) []byte {
	bm := make([]byte, (int(count)+7)/8)
	for _, idx := range indexes {
		if idx < 0 || uint32(idx) >= count {
			continue
		}
		bm[idx/8] |= 1 << uint(idx%8)
	}
	return bm
}

// bitmapB64 把位图编码成 base64url。
func bitmapB64(bm []byte) string { return auth.B64.EncodeToString(bm) }
