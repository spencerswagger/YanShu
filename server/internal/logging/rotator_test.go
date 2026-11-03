package logging

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileNameRule(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if _, err := r.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	want := filepath.Join(dir, "yanshu-server-"+day+".log")
	if r.Path() != want {
		t.Fatalf("path = %q, want %q", r.Path(), want)
	}
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("content = %q", data)
	}
}

func TestRotatesAcrossDays(t *testing.T) {
	dir := t.TempDir()
	r, err := New(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	day1 := time.Date(2026, 11, 2, 23, 59, 0, 0, time.UTC)
	day2 := day1.Add(2 * time.Minute)
	r.now = func() time.Time { return day1 }
	if _, err := r.Write([]byte("a\n")); err != nil {
		t.Fatal(err)
	}
	first := r.Path()

	r.now = func() time.Time { return day2 }
	if _, err := r.Write([]byte("b\n")); err != nil {
		t.Fatal(err)
	}
	if r.Path() == first {
		t.Fatal("expected rotation to a new day file")
	}
	if _, err := os.Stat(filepath.Join(dir, "yanshu-server-2026-11-02.log")); err != nil {
		t.Fatalf("day1 file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "yanshu-server-2026-11-03.log")); err != nil {
		t.Fatalf("day2 file missing: %v", err)
	}
}

func TestRetentionPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	// 预置一个超期文件与一个无关文件。
	old := filepath.Join(dir, "yanshu-server-2020-01-01.log")
	if err := os.WriteFile(old, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "keep-me.log")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o640); err != nil {
		t.Fatal(err)
	}

	r, err := New(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expired log not pruned: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
}
