// Package blob 存不透明密文块（本地磁盘）。
//
// 目录布局只有一个来源：包 ID。磁盘上不出现任何用户内容——
// 没有文件名、没有 MIME、没有块头、没有明文；块头由接收方按
// docs/CRYPTO-PACK.md §6.3 本地重建，服务端从不解析它。
//
//	<root>/<pkg[0:2]>/<pkg>/prelude        prelude 原始字节
//	<root>/<pkg[0:2]>/<pkg>/chunks/<idx>   单块切片 (CT ‖ TAG)
package blob

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spencerswagger/YanShu/server/internal/gm"
)

// 语义化错误。
var (
	ErrNotFound = errors.New("blob: not found")
	ErrConflict = errors.New("blob: conflict")
	ErrTooLarge = errors.New("blob: too large")
	ErrBadID    = errors.New("blob: bad transfer id")
)

var pkgIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// PutResult 是一次写入结果。
type PutResult struct {
	Bytes     int64
	Digest    []byte
	Duplicate bool
}

// ReadSeekCloser 让 handler 能用 http.ServeContent 处理单区间 Range（API.md §8.1）。
type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

// Store 是密文块存储接口；换成对象存储时只换实现。
type Store interface {
	PutPrelude(transferID string, data []byte) (PutResult, error)
	PutChunk(transferID string, index uint32, data []byte) (PutResult, error)
	OpenPrelude(transferID string) (ReadSeekCloser, int64, error)
	OpenChunk(transferID string, index uint32) (ReadSeekCloser, int64, error)
	Purge(transferID string) error
	Usage(transferID string) (int64, error)
}

// Disk 是本地磁盘实现。
type Disk struct {
	root string
}

// NewDisk 准备根目录。
func NewDisk(root string) (*Disk, error) {
	if root == "" {
		return nil, errors.New("blob: root is empty")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("blob: create root: %w", err)
	}
	return &Disk{root: root}, nil
}

func (d *Disk) pkgDir(transferID string) (string, error) {
	if !pkgIDPattern.MatchString(transferID) {
		return "", ErrBadID
	}
	return filepath.Join(d.root, transferID[:2], transferID), nil
}

func (d *Disk) put(dir, name string, data []byte) (PutResult, error) {
	sum := gm.SM3(data)
	res := PutResult{Bytes: int64(len(data)), Digest: sum[:]}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return PutResult{}, fmt.Errorf("blob: mkdir: %w", err)
	}
	target := filepath.Join(dir, name)

	if existing, err := os.Stat(target); err == nil {
		if existing.Size() != int64(len(data)) {
			return PutResult{}, ErrConflict
		}
		oldSum, err := hashFile(target)
		if err != nil {
			return PutResult{}, err
		}
		if string(oldSum) != string(res.Digest) {
			return PutResult{}, ErrConflict
		}
		res.Duplicate = true
		return res, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return PutResult{}, fmt.Errorf("blob: stat: %w", err)
	}

	// 先写临时文件再 rename，避免半个块被读到。
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return PutResult{}, fmt.Errorf("blob: rand: %w", err)
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(suffix[:]))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return PutResult{}, fmt.Errorf("blob: create tmp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return PutResult{}, fmt.Errorf("blob: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return PutResult{}, fmt.Errorf("blob: sync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return PutResult{}, fmt.Errorf("blob: close: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return PutResult{}, fmt.Errorf("blob: rename: %w", err)
	}
	return res, nil
}

// PutPrelude 写 prelude。
func (d *Disk) PutPrelude(transferID string, data []byte) (PutResult, error) {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return PutResult{}, err
	}
	return d.put(dir, "prelude", data)
}

// PutChunk 写单块切片。
func (d *Disk) PutChunk(transferID string, index uint32, data []byte) (PutResult, error) {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return PutResult{}, err
	}
	return d.put(filepath.Join(dir, "chunks"), fmt.Sprintf("%08d", index), data)
}

// OpenPrelude 读 prelude。
func (d *Disk) OpenPrelude(transferID string) (ReadSeekCloser, int64, error) {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return nil, 0, err
	}
	return openFile(filepath.Join(dir, "prelude"))
}

// OpenChunk 读单块。
func (d *Disk) OpenChunk(transferID string, index uint32) (ReadSeekCloser, int64, error) {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return nil, 0, err
	}
	return openFile(filepath.Join(dir, "chunks", fmt.Sprintf("%08d", index)))
}

// Purge 真删：整包目录物理移除（不是软删、不是改名）。
func (d *Disk) Purge(transferID string) error {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("blob: purge: %w", err)
	}
	// 顺手清掉空的二级目录，不留"这里曾经有包"的痕迹。
	parent := filepath.Dir(dir)
	if entries, err := os.ReadDir(parent); err == nil && len(entries) == 0 {
		_ = os.Remove(parent)
	}
	return nil
}

// Usage 返回该包占用字节数。
func (d *Disk) Usage(transferID string) (int64, error) {
	dir, err := d.pkgDir(transferID)
	if err != nil {
		return 0, err
	}
	var total int64
	err = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	return total, err
}

func openFile(path string) (ReadSeekCloser, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, fmt.Errorf("blob: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("blob: stat: %w", err)
	}
	return f, info.Size(), nil
}

func hashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("blob: open for hash: %w", err)
	}
	defer f.Close()
	d := gm.NewSM3()
	if _, err := io.Copy(d, f); err != nil {
		return nil, fmt.Errorf("blob: hash: %w", err)
	}
	return d.Sum(nil), nil
}
