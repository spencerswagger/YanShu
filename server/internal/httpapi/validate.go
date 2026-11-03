package httpapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

var errBadEncoding = errors.New("invalid base64url")

// decodeB64 解 base64url 无填充（API.md §0.1：拒绝 `=` 与 len%4==1）。
func decodeB64(s string) ([]byte, error) {
	if strings.ContainsRune(s, '=') || len(s)%4 == 1 {
		return nil, errBadEncoding
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errBadEncoding
	}
	return b, nil
}

// decodePublicKey 校验并解码未压缩 SM2 公钥（0x04 ‖ X32 ‖ Y32）。
// 只做形状校验；点是否在曲线上由验签实现负责。
func decodePublicKey(s string) ([]byte, error) {
	b, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 65 || b[0] != 0x04 {
		return nil, errors.New("public key must be 65-byte uncompressed point")
	}
	return b, nil
}

// sanitizeNickname：UTF-8 NFC（由客户端保证）、1..32 字节、不含控制字符与 <>（API.md §1.1）。
func sanitizeNickname(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || !utf8.ValidString(s) {
		return "", errors.New("nickname must be non-empty valid UTF-8")
	}
	if len(s) > 32 {
		return "", errors.New("nickname must be at most 32 bytes")
	}
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || r == '<' || r == '>' {
			return "", errors.New("nickname contains forbidden characters")
		}
	}
	return s, nil
}

// plaintextChunkLen 返回第 index 块的明文长度（CRYPTO-PACK §4.2）。
func plaintextChunkLen(chunkSize uint32, plaintextSize uint64, chunkCount, index uint32) uint32 {
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

// expectedChunkLen 是块切片长度 = 明文块长 + 16 字节 GCM tag（API.md §6.4）。
func expectedChunkLen(chunkSize uint32, plaintextSize uint64, chunkCount, index uint32) uint32 {
	return plaintextChunkLen(chunkSize, plaintextSize, chunkCount, index) + 16
}

// expectedChunkCount 由明文总长与块大小推块数；空文件 1 块（CRYPTO-PACK §4.2）。
func expectedChunkCount(plaintextSize uint64, chunkSize uint32) uint32 {
	if chunkSize == 0 {
		return 0
	}
	if plaintextSize == 0 {
		return 1
	}
	return uint32((plaintextSize + uint64(chunkSize) - 1) / uint64(chunkSize))
}

// buildBitmap 生成「已收块」位图：第 i 块在 bit (7 - i%8)（MSB 优先，API.md §6.5）。
func buildBitmap(indexes []int, count uint32) []byte {
	bm := make([]byte, (int(count)+7)/8)
	for _, idx := range indexes {
		if idx < 0 || uint32(idx) >= count {
			continue
		}
		bm[idx/8] |= 1 << uint(7-idx%8)
	}
	return bm
}

// missingRanges 把缺失块合并成连续区间。
func missingRanges(present []int, count uint32) []spec.MissingRange {
	set := make(map[int]struct{}, len(present))
	for _, idx := range present {
		set[idx] = struct{}{}
	}
	out := make([]spec.MissingRange, 0, 4)
	var start int = -1
	for i := 0; i < int(count); i++ {
		_, ok := set[i]
		if !ok && start < 0 {
			start = i
		}
		if ok && start >= 0 {
			out = append(out, spec.MissingRange{Start: uint32(start), Count: uint32(i - start)})
			start = -1
		}
	}
	if start >= 0 {
		out = append(out, spec.MissingRange{Start: uint32(start), Count: uint32(int(count) - start)})
	}
	return out
}

// encodeCursor 把 keyset 位置编码成不透明字符串。
func encodeCursor(createdAt time.Time, id string) string {
	raw := fmt.Sprintf("%d|%s", createdAt.UTC().UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor 解出不透明游标。
func decodeCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", errBadEncoding
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 || len(parts[1]) != 32 {
		return time.Time{}, "", errBadEncoding
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", errBadEncoding
	}
	return time.Unix(0, nanos).UTC(), parts[1], nil
}

// uploadToken 取上传侧能力凭证。
func uploadToken(r *http.Request) string { return r.Header.Get(spec.HeaderUploadToken) }

// downloadID 取下载租约 ID。
func downloadID(r *http.Request) string { return r.Header.Get(spec.HeaderDownloadID) }
