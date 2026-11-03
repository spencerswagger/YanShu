// Package logging 提供按日滚动的文件日志写入器。
//
// 为什么需要它：验收要求「日志可定位、可复扫」，而只写 stdout 时日志落在哪完全取决于
// 部署方怎么重定向 —— 那等于把证据的可复现性交给运气。这里给出确定的文件名规则：
//
//	<dir>/yanshu-server-YYYY-MM-DD.log（UTC 日期）
//
// 滚动在写入时惰性触发（跨天第一个日志行时换文件），并顺带清理超过保留天数的旧文件。
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FilePrefix 是日志文件名前缀。
const FilePrefix = "yanshu-server-"

// Rotator 是「按 UTC 日期滚动」的 io.Writer。
type Rotator struct {
	mu        sync.Mutex
	dir       string
	retention int
	file      *os.File
	day       string
	now       func() time.Time
}

// New 打开当天的日志文件，并清理超过 retention 天的旧文件。
func New(dir string, retentionDays int) (*Rotator, error) {
	if dir == "" {
		return nil, fmt.Errorf("logging: empty log dir")
	}
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("logging: create dir: %w", err)
	}
	r := &Rotator{dir: dir, retention: retentionDays, now: func() time.Time { return time.Now().UTC() }}
	if err := r.openLocked(r.now()); err != nil {
		return nil, err
	}
	r.pruneLocked(r.now())
	return r, nil
}

// Path 返回当前正在写的文件路径。
func (r *Rotator) Path() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return ""
	}
	return r.file.Name()
}

// Write 在跨天时切换文件后写入。
func (r *Rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if dayKey(now) != r.day {
		if err := r.openLocked(now); err != nil {
			return 0, err
		}
		r.pruneLocked(now)
	}
	if r.file == nil {
		return 0, fmt.Errorf("logging: no open file")
	}
	return r.file.Write(p)
}

// Close 关闭当前文件。
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *Rotator) openLocked(now time.Time) error {
	day := dayKey(now)
	path := filepath.Join(r.dir, FilePrefix+day+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("logging: open %s: %w", path, err)
	}
	if r.file != nil {
		_ = r.file.Close()
	}
	r.file = f
	r.day = day
	return nil
}

// pruneLocked 删除超过保留期的日志文件（只删本服务命名规则内的文件）。
func (r *Rotator) pruneLocked(now time.Time) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}
	cutoff := now.AddDate(0, 0, -r.retention)
	var old []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, FilePrefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, FilePrefix), ".log")
		t, err := time.Parse("2006-01-02", day)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			old = append(old, name)
		}
	}
	sort.Strings(old)
	for _, name := range old {
		_ = os.Remove(filepath.Join(r.dir, name))
	}
}

func dayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }
