package blob

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func newDisk(t *testing.T) *Disk {
	t.Helper()
	d, err := NewDisk(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

const testID = "0123456789abcdef0123456789abcdef"

func TestPutGetPrelude(t *testing.T) {
	d := newDisk(t)
	data := []byte("opaque-prelude-bytes")
	res, err := d.PutPrelude(testID, data)
	if err != nil {
		t.Fatal(err)
	}
	if res.Duplicate || res.Bytes != int64(len(data)) || len(res.Digest) != 32 {
		t.Fatalf("unexpected result: %+v", res)
	}

	rc, size, err := d.OpenPrelude(testID)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, data) || size != int64(len(data)) {
		t.Fatalf("roundtrip mismatch: %q size=%d", got, size)
	}

	again, err := d.PutPrelude(testID, data)
	if err != nil || !again.Duplicate {
		t.Fatalf("idempotent put: %+v err=%v", again, err)
	}
	if _, err := d.PutPrelude(testID, []byte("different")); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting put = %v, want ErrConflict", err)
	}
}

func TestChunksAreSeparate(t *testing.T) {
	d := newDisk(t)
	if _, err := d.PutChunk(testID, 0, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutChunk(testID, 1, []byte("b")); err != nil {
		t.Fatal(err)
	}
	for i, want := range [][]byte{[]byte("a"), []byte("b")} {
		rc, _, err := d.OpenChunk(testID, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(got, want) {
			t.Fatalf("chunk %d = %q, want %q", i, got, want)
		}
	}
	if _, _, err := d.OpenChunk(testID, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing chunk = %v, want ErrNotFound", err)
	}
}

func TestPurgeReallyDeletes(t *testing.T) {
	d := newDisk(t)
	if _, err := d.PutPrelude(testID, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PutChunk(testID, 0, []byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := d.Purge(testID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(d.root, testID[:2], testID)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("package dir survived purge: %v", err)
	}
	if _, _, err := d.OpenPrelude(testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open after purge = %v, want ErrNotFound", err)
	}
}

func TestRejectsTraversalIDs(t *testing.T) {
	d := newDisk(t)
	for _, bad := range []string{"", "../etc", "0123456789abcdef0123456789abcdeZ", "0123456789abcdef0123456789abcde"} {
		if _, err := d.PutPrelude(bad, []byte("x")); !errors.Is(err, ErrBadID) {
			t.Fatalf("PutPrelude(%q) = %v, want ErrBadID", bad, err)
		}
	}
}

func TestDiskLayoutHasNoUserContent(t *testing.T) {
	d := newDisk(t)
	if _, err := d.PutChunk(testID, 3, []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	var names []string
	err := filepath.Walk(d.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(d.root, path)
			names = append(names, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(testID[:2], testID, "chunks", "00000003")
	if len(names) != 1 || names[0] != want {
		t.Fatalf("disk layout = %v, want [%s]", names, want)
	}
}
