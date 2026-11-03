// Package packet 只做 `.yspk` 信封的**结构切分**：读出 HEADER 里的长度字段，
// 把文件切成 prelude 与块切片。它不做任何加解密，也不碰清单/密钥。
//
// 依据 docs/CRYPTO-PACK.md：§4.2（段表与偏移）、§5（HEADER 字段）、§6.2（块记录）、
// §6.3（传输切片 = CHUNK_CT ‖ TAG，**不含** 16 字节块头）。
//
// `.yspk` 文件里每块是「16 字节块头 + 密文 + 16 字节 tag」；上传给服务端的是
// 去掉块头后的切片。这些字段是**结构性明文**，端侧与接收方都要读；服务端从不解析，
// 只按调用方声明的长度存取。
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// 常量与 CRYPTO-PACK §2 / §4 / §5 对齐。
const (
	Magic        = "YSPK"
	VersionMajor = 1
	VersionMinor = 0
	HeaderLen    = 112

	offMagic         = 0
	offVersionMajor  = 4
	offVersionMinor  = 5
	offHeaderLen     = 6
	offChunkSize     = 16
	offChunkCount    = 20
	offPlaintextSize = 24
	offWrappedKeyLen = 32
	offManifestLen   = 40
	offManifestPTLen = 48
	offSenderPubLen  = 52
	offSigLen        = 72
	offReserved      = 80

	// chunkRecordHeaderLen 是块记录的 16 字节块头（CRYPTO-PACK §6.2）。
	chunkRecordHeaderLen = 16
)

// 解析错误。
var (
	ErrTooShort     = errors.New("packet: file shorter than header")
	ErrBadMagic     = errors.New("packet: magic is not YSPK")
	ErrBadVersion   = errors.New("packet: unsupported version")
	ErrBadHeader    = errors.New("packet: header fields are inconsistent")
	ErrLengthBroken = errors.New("packet: file length does not match header")
)

// Envelope 是一个切分好的加密包。
type Envelope struct {
	ChunkSize     uint32
	ChunkCount    uint32
	PlaintextSize uint64
	PreludeLen    int
	SigLen        int
	ManifestLen   int

	// Prelude = HEADER ‖ SENDER_PUB ‖ WRAPPED_KEY ‖ MANIFEST_SEC ‖ SIG_SEC
	Prelude []byte
	// SenderPublicKey 是包内 SENDER_PUB（65 字节未压缩点），用于派生发送方码。
	SenderPublicKey []byte
	// Chunks[i] = CHUNK_CT ‖ TAG（不含 16 字节块头，CRYPTO-PACK §6.3）
	Chunks [][]byte
}

// Parse 读取并校验信封结构。不做解密、不读清单明文。
func Parse(data []byte) (Envelope, error) {
	if len(data) < HeaderLen {
		return Envelope{}, fmt.Errorf("%w: got %d bytes", ErrTooShort, len(data))
	}
	if string(data[offMagic:offMagic+4]) != Magic {
		return Envelope{}, ErrBadMagic
	}
	if data[offVersionMajor] != VersionMajor || data[offVersionMinor] != VersionMinor {
		return Envelope{}, fmt.Errorf("%w: %d.%d", ErrBadVersion, data[offVersionMajor], data[offVersionMinor])
	}
	headerLen := int(binary.BigEndian.Uint16(data[offHeaderLen:]))
	if headerLen != HeaderLen {
		return Envelope{}, fmt.Errorf("%w: HEADER_LEN=%d", ErrBadHeader, headerLen)
	}

	env := Envelope{
		ChunkSize:     binary.BigEndian.Uint32(data[offChunkSize:]),
		ChunkCount:    binary.BigEndian.Uint32(data[offChunkCount:]),
		PlaintextSize: binary.BigEndian.Uint64(data[offPlaintextSize:]),
	}
	wrappedKeyLen := binary.BigEndian.Uint64(data[offWrappedKeyLen:])
	manifestLen := binary.BigEndian.Uint64(data[offManifestLen:])
	manifestPTLen := binary.BigEndian.Uint32(data[offManifestPTLen:])
	senderPubLen := binary.BigEndian.Uint32(data[offSenderPubLen:])
	env.SigLen = int(binary.BigEndian.Uint64(data[offSigLen:]))
	env.ManifestLen = int(manifestLen)

	if env.ChunkSize < 16 || env.ChunkSize > 1048576 {
		return Envelope{}, fmt.Errorf("%w: CHUNK_SIZE=%d", ErrBadHeader, env.ChunkSize)
	}
	if env.ChunkCount < 1 || env.ChunkCount > 1048576 {
		return Envelope{}, fmt.Errorf("%w: CHUNK_COUNT=%d", ErrBadHeader, env.ChunkCount)
	}
	if env.PlaintextSize > 4294967296 {
		return Envelope{}, fmt.Errorf("%w: PLAINTEXT_SIZE=%d", ErrBadHeader, env.PlaintextSize)
	}
	if senderPubLen != 65 {
		return Envelope{}, fmt.Errorf("%w: SENDER_PUB_LEN=%d", ErrBadHeader, senderPubLen)
	}
	if wrappedKeyLen != 129 {
		return Envelope{}, fmt.Errorf("%w: WRAPPED_KEY_LEN=%d", ErrBadHeader, wrappedKeyLen)
	}
	if uint64(manifestPTLen)+16 != manifestLen {
		return Envelope{}, fmt.Errorf("%w: MANIFEST_LEN=%d MANIFEST_PT_LEN=%d", ErrBadHeader, manifestLen, manifestPTLen)
	}
	if env.SigLen < 70 || env.SigLen > 72 {
		return Envelope{}, fmt.Errorf("%w: SIG_LEN=%d", ErrBadHeader, env.SigLen)
	}
	for _, b := range data[offReserved : offReserved+32] {
		if b != 0 {
			return Envelope{}, fmt.Errorf("%w: RESERVED is not zero", ErrBadHeader)
		}
	}
	if want := expectedChunkCount(env.PlaintextSize, env.ChunkSize); env.ChunkCount != want {
		return Envelope{}, fmt.Errorf("%w: CHUNK_COUNT=%d want %d", ErrBadHeader, env.ChunkCount, want)
	}

	env.PreludeLen = HeaderLen + int(senderPubLen) + int(wrappedKeyLen) + int(manifestLen) + env.SigLen
	if env.PreludeLen > len(data) {
		return Envelope{}, fmt.Errorf("%w: prelude %d > file %d", ErrLengthBroken, env.PreludeLen, len(data))
	}
	env.Prelude = data[:env.PreludeLen]
	env.SenderPublicKey = data[HeaderLen : HeaderLen+int(senderPubLen)]

	pos := env.PreludeLen
	env.Chunks = make([][]byte, 0, env.ChunkCount)
	for i := uint32(0); i < env.ChunkCount; i++ {
		if pos+chunkRecordHeaderLen > len(data) {
			return Envelope{}, fmt.Errorf("%w: chunk %d header truncated", ErrLengthBroken, i)
		}
		hdr := data[pos : pos+chunkRecordHeaderLen]
		index := binary.BigEndian.Uint32(hdr[0:])
		ptLen := binary.BigEndian.Uint32(hdr[4:])
		ctLen := binary.BigEndian.Uint32(hdr[8:])
		lastFlag := hdr[12]
		if index != i {
			return Envelope{}, fmt.Errorf("%w: chunk %d has CHUNK_INDEX=%d", ErrBadHeader, i, index)
		}
		if ctLen != ptLen {
			return Envelope{}, fmt.Errorf("%w: chunk %d CT_LEN %d != PT_LEN %d", ErrBadHeader, i, ctLen, ptLen)
		}
		if want := plaintextChunkLen(env.ChunkSize, env.PlaintextSize, env.ChunkCount, i); ptLen != want {
			return Envelope{}, fmt.Errorf("%w: chunk %d PT_LEN %d want %d", ErrBadHeader, i, ptLen, want)
		}
		wantLast := byte(0)
		if i == env.ChunkCount-1 {
			wantLast = 1
		}
		if lastFlag != wantLast {
			return Envelope{}, fmt.Errorf("%w: chunk %d LAST_FLAG=%d", ErrBadHeader, i, lastFlag)
		}
		if hdr[13] != 0 || hdr[14] != 0 || hdr[15] != 0 {
			return Envelope{}, fmt.Errorf("%w: chunk %d RESERVED not zero", ErrBadHeader, i)
		}
		pos += chunkRecordHeaderLen
		end := pos + int(ctLen) + 16
		if end > len(data) {
			return Envelope{}, fmt.Errorf("%w: chunk %d truncated", ErrLengthBroken, i)
		}
		env.Chunks = append(env.Chunks, data[pos:end])
		pos = end
	}
	if pos != len(data) {
		return Envelope{}, fmt.Errorf("%w: %d trailing bytes", ErrLengthBroken, len(data)-pos)
	}
	return env, nil
}

func plaintextChunkLen(chunkSize uint32, plaintextSize uint64, chunkCount, index uint32) uint32 {
	if index < chunkCount-1 {
		return chunkSize
	}
	used := uint64(chunkSize) * uint64(chunkCount-1)
	if plaintextSize <= used {
		return 0
	}
	return uint32(plaintextSize - used)
}

func expectedChunkCount(plaintextSize uint64, chunkSize uint32) uint32 {
	if plaintextSize == 0 {
		return 1
	}
	return uint32((plaintextSize + uint64(chunkSize) - 1) / uint64(chunkSize))
}

// CiphertextBytes 返回包内密文总字节数（prelude + 全部块切片）。
func (e Envelope) CiphertextBytes() int64 {
	total := int64(e.PreludeLen)
	for _, c := range e.Chunks {
		total += int64(len(c))
	}
	return total
}
