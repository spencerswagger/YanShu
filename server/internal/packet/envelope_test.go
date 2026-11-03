package packet

import (
	"encoding/binary"
	"testing"
)

// build 造一个**结构合法**的信封用于解析测试（内容为随机占位字节，非真密文）。
func build(chunkSize uint32, plaintextSize uint64, manifestLen uint64, sigLen int) []byte {
	chunkCount := expectedChunkCount(plaintextSize, chunkSize)
	header := make([]byte, HeaderLen)
	copy(header[0:], Magic)
	header[4] = VersionMajor
	header[5] = VersionMinor
	binary.BigEndian.PutUint16(header[6:], HeaderLen)
	binary.BigEndian.PutUint32(header[16:], chunkSize)
	binary.BigEndian.PutUint32(header[20:], chunkCount)
	binary.BigEndian.PutUint64(header[24:], plaintextSize)
	binary.BigEndian.PutUint64(header[32:], 129)
	binary.BigEndian.PutUint64(header[40:], manifestLen)
	binary.BigEndian.PutUint32(header[48:], uint32(manifestLen-16))
	binary.BigEndian.PutUint32(header[52:], 65)
	binary.BigEndian.PutUint64(header[72:], uint64(sigLen))

	out := append([]byte(nil), header...)
	out = append(out, make([]byte, 65)...)
	out = append(out, make([]byte, 129)...)
	out = append(out, make([]byte, manifestLen)...)
	out = append(out, make([]byte, sigLen)...)
	for i := uint32(0); i < chunkCount; i++ {
		pt := plaintextChunkLen(chunkSize, plaintextSize, chunkCount, i)
		hdr := make([]byte, chunkRecordHeaderLen)
		binary.BigEndian.PutUint32(hdr[0:], i)
		binary.BigEndian.PutUint32(hdr[4:], pt)
		binary.BigEndian.PutUint32(hdr[8:], pt)
		if i == chunkCount-1 {
			hdr[12] = 1
		}
		out = append(out, hdr...)
		out = append(out, make([]byte, int(pt)+16)...)
	}
	return out
}

func TestParseSingleChunk(t *testing.T) {
	data := build(1048576, 5, 109, 70)
	env, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if env.ChunkCount != 1 || len(env.Chunks) != 1 || len(env.Chunks[0]) != 21 {
		t.Fatalf("unexpected: count=%d chunks=%d", env.ChunkCount, len(env.Chunks))
	}
	if env.PreludeLen != 112+65+129+109+70 {
		t.Fatalf("prelude len = %d", env.PreludeLen)
	}
	if len(env.SenderPublicKey) != 65 {
		t.Fatalf("sender pub len = %d", len(env.SenderPublicKey))
	}
	// 传输字节 = prelude + 切片；文件里每块还多 16 字节块头。
	if env.CiphertextBytes()+int64(chunkRecordHeaderLen)*int64(env.ChunkCount) != int64(len(data)) {
		t.Fatalf("ciphertext bytes = %d, file = %d", env.CiphertextBytes(), len(data))
	}
}

func TestParseMultiChunk(t *testing.T) {
	data := build(32, 80, 190, 71)
	env, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if env.ChunkCount != 3 || len(env.Chunks) != 3 {
		t.Fatalf("chunk count = %d", env.ChunkCount)
	}
	want := []int{48, 48, 32}
	for i, n := range want {
		if len(env.Chunks[i]) != n {
			t.Fatalf("chunk %d len = %d, want %d", i, len(env.Chunks[i]), n)
		}
	}
}

func TestParseEmptyFile(t *testing.T) {
	data := build(1048576, 0, 100, 70)
	env, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if env.ChunkCount != 1 || len(env.Chunks[0]) != 16 {
		t.Fatalf("empty file must have one 16-byte tag-only chunk: %+v", env.Chunks)
	}
}

func TestParseRejects(t *testing.T) {
	good := build(32, 80, 190, 71)
	cases := []struct {
		name string
		mut  func([]byte)
	}{
		{"short", func(b []byte) {}},
		{"magic", func(b []byte) { b[0] = 'X' }},
		{"version", func(b []byte) { b[4] = 2 }},
		{"header len", func(b []byte) { binary.BigEndian.PutUint16(b[6:], 120) }},
		{"chunk size", func(b []byte) { binary.BigEndian.PutUint32(b[16:], 8) }},
		{"sender pub len", func(b []byte) { binary.BigEndian.PutUint32(b[52:], 64) }},
		{"wrapped key len", func(b []byte) { binary.BigEndian.PutUint64(b[32:], 128) }},
		{"sig len", func(b []byte) { binary.BigEndian.PutUint64(b[72:], 69) }},
		{"reserved", func(b []byte) { b[80] = 1 }},
		{"trailing", func(b []byte) { _ = b }},
	}
	for _, c := range cases {
		data := append([]byte(nil), good...)
		switch c.name {
		case "short":
			data = data[:100]
		case "trailing":
			data = append(data, 0x00)
		default:
			c.mut(data)
		}
		if _, err := Parse(data); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
	}
}

func TestParseChunkCountMismatch(t *testing.T) {
	data := build(32, 80, 190, 71)
	binary.BigEndian.PutUint32(data[20:], 2)
	if _, err := Parse(data); err == nil {
		t.Fatal("chunk_count mismatch accepted")
	}
}
