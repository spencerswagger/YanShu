package ratelimit

import (
	"sync"
	"time"
)

// Lockout 是失败锁定接口（API.md §11.3：连续失败 → 423 CODE_LOCKED，逐次翻倍）。
type Lockout interface {
	// Locked 查询是否处于锁定中。
	Locked(key string) (bool, time.Duration)
	// Hit 记一次失败；达到阈值时锁定并返回时长。
	Hit(key string, threshold int, base, max time.Duration) (bool, time.Duration)
	// Reset 清零（成功一次即解锁，降低误伤）。
	Reset(key string)
}

type lockState struct {
	strikes     int
	lockedUntil time.Time
	lastTouch   time.Time
}

// MemoryLockout 是进程内实现。
type MemoryLockout struct {
	mu    sync.Mutex
	state map[string]*lockState
	now   func() time.Time
	ops   int
}

// NewMemoryLockout 构造内存锁定器。
func NewMemoryLockout() *MemoryLockout {
	return &MemoryLockout{state: make(map[string]*lockState), now: time.Now}
}

// Locked 查询锁定状态。
func (m *MemoryLockout) Locked(key string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.state[key]
	if !ok {
		return false, 0
	}
	now := m.now()
	if now.Before(s.lockedUntil) {
		return true, s.lockedUntil.Sub(now)
	}
	return false, 0
}

// Hit 记一次失败并按 1→2→4…（上限 max）升级锁定时长。
func (m *MemoryLockout) Hit(key string, threshold int, base, max time.Duration) (bool, time.Duration) {
	if threshold <= 0 {
		return false, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	s, ok := m.state[key]
	if !ok {
		s = &lockState{}
		m.state[key] = s
	}
	s.strikes++
	s.lastTouch = now
	m.maybeGC(now)
	if s.strikes < threshold {
		return false, 0
	}
	// 第 threshold 次锁定 base，之后逐次翻倍。
	shift := s.strikes - threshold
	d := base
	for i := 0; i < shift && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	s.lockedUntil = now.Add(d)
	return true, d
}

// Reset 清零失败计数与锁定。
func (m *MemoryLockout) Reset(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.state, key)
}

func (m *MemoryLockout) maybeGC(now time.Time) {
	m.ops++
	if m.ops%512 != 0 {
		return
	}
	cutoff := now.Add(-2 * time.Hour)
	for k, s := range m.state {
		if s.lastTouch.Before(cutoff) && s.lockedUntil.Before(now) {
			delete(m.state, k)
		}
	}
}
