// Package ratelimit 是限速与失败锁定的骨架实现。
//
// 当前是进程内内存实现，够单实例骨架用；多实例时把 Limiter 换成 Redis 版本即可，
// 接口不变。真实阈值待 docs/API.md 对齐（见 spec/limits.go）。
package ratelimit

import (
	"sync"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// Decision 是一次限速判定的结果。
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	RetryAfter time.Duration
}

// Limiter 是限速接口。
type Limiter interface {
	// Take 从 key 的令牌桶里取一个令牌。
	Take(key string, l spec.Limit) Decision
	// Locked 查询 key 是否处于失败锁定中。
	Locked(key string) (bool, time.Duration)
	// Fail 记一次失败；达到阈值即锁定。
	Fail(key string, threshold int, lockFor time.Duration) (bool, time.Duration)
	// Succeed 清零失败计数。
	Succeed(key string)
}

type bucket struct {
	tokens   float64
	capacity float64
	rate     float64 // 每秒补充
	last     time.Time
}

type failState struct {
	count     int
	lockedTo  time.Time
	lastTouch time.Time
}

// Memory 是进程内实现。
type Memory struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	failures map[string]*failState
	now      func() time.Time
	ops      int
}

// NewMemory 构造内存限速器。
func NewMemory() *Memory {
	return &Memory{
		buckets:  make(map[string]*bucket),
		failures: make(map[string]*failState),
		now:      time.Now,
	}
}

// Take 实现令牌桶。
func (m *Memory) Take(key string, l spec.Limit) Decision {
	if l.Max <= 0 || l.WindowSeconds <= 0 {
		return Decision{Allowed: true}
	}
	capacity := l.Burst
	if capacity <= 0 {
		capacity = l.Max
	}
	rate := float64(l.Max) / float64(l.WindowSeconds)

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	b, ok := m.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(capacity), capacity: float64(capacity), rate: rate, last: now}
		m.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rate
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
			b.last = now
		}
		if b.rate != rate || b.capacity != float64(capacity) {
			b.rate = rate
			b.capacity = float64(capacity)
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
		}
	}
	m.maybeGC(now)
	if b.tokens < 1 {
		retry := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		if retry < time.Second {
			retry = time.Second
		}
		return Decision{Allowed: false, Limit: l.Max, Remaining: 0, RetryAfter: retry}
	}
	b.tokens--
	return Decision{Allowed: true, Limit: l.Max, Remaining: int(b.tokens)}
}

// Locked 查询锁定状态。
func (m *Memory) Locked(key string) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.failures[key]
	if !ok {
		return false, 0
	}
	now := m.now()
	if now.Before(f.lockedTo) {
		return true, f.lockedTo.Sub(now)
	}
	if !f.lockedTo.IsZero() && !now.Before(f.lockedTo) {
		// 锁定到期，计数归零。
		delete(m.failures, key)
	}
	return false, 0
}

// Fail 记失败并在阈值处锁定。
func (m *Memory) Fail(key string, threshold int, lockFor time.Duration) (bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	f, ok := m.failures[key]
	if !ok {
		f = &failState{}
		m.failures[key] = f
	}
	f.count++
	f.lastTouch = now
	if threshold > 0 && f.count >= threshold {
		f.lockedTo = now.Add(lockFor)
		return true, lockFor
	}
	return false, 0
}

// Succeed 清零失败计数。
func (m *Memory) Succeed(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.failures, key)
}

// maybeGC 偶尔清理长期不用的键，避免内存无限增长。
func (m *Memory) maybeGC(now time.Time) {
	m.ops++
	if m.ops%1024 != 0 {
		return
	}
	cutoff := now.Add(-10 * time.Minute)
	for k, b := range m.buckets {
		if b.last.Before(cutoff) {
			delete(m.buckets, k)
		}
	}
	for k, f := range m.failures {
		if f.lastTouch.Before(cutoff) && f.lockedTo.Before(now) {
			delete(m.failures, k)
		}
	}
}
