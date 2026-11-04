// Package signal 维护直传信令的在线表（按 4 位码登记连接）与订阅关系。
//
// 语义（API.md §9.3）：
//   - 一个码可以有多条连接（同一个人多端/多标签页）：消息按连接粒度投递，投递给该码的**全部**连接；
//   - 断连即摘除；码没有连接即视为离线（用于 PEER_UNREACHABLE 与 PRESENCE_CHANGED）；
//   - 本包只做登记与投递，不解析信令内容。
package signal

import (
	"sync"
)

// Conn 是 Hub 需要的连接抽象（由 httpapi 实现），便于单测替换。
type Conn interface {
	Code() string
	Send(v any) error
}

// Hub 是在线表 + 订阅表。
type Hub struct {
	mu     sync.RWMutex
	conns  map[Conn]string              // 连接 → 码
	byCode map[string]map[Conn]struct{} // 码 → 连接集合
	subs   map[Conn]map[string]struct{} // 连接 → 订阅的码集合
}

// New 创建空 Hub。
func New() *Hub {
	return &Hub{
		conns:  make(map[Conn]string),
		byCode: make(map[string]map[Conn]struct{}),
		subs:   make(map[Conn]map[string]struct{}),
	}
}

// Add 登记一条已认证连接。
func (h *Hub) Add(c Conn, code string) {
	h.mu.Lock()
	h.conns[c] = code
	if h.byCode[code] == nil {
		h.byCode[code] = map[Conn]struct{}{}
	}
	_, existed := h.byCode[code][c]
	h.byCode[code][c] = struct{}{}
	becameOnline := !existed && len(h.byCode[code]) == 1
	h.mu.Unlock()

	if becameOnline {
		h.notifyPresence(code, true)
	}
}

// Remove 摘除连接；返回该码是否因此离线。
func (h *Hub) Remove(c Conn) {
	h.mu.Lock()
	code, ok := h.conns[c]
	if !ok {
		h.mu.Unlock()
		return
	}
	delete(h.conns, c)
	if set := h.byCode[code]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(h.byCode, code)
		}
	}
	delete(h.subs, c)
	offline := len(h.byCode[code]) == 0
	h.mu.Unlock()

	if offline {
		h.notifyPresence(code, false)
	}
}

// Online 判断某码当前是否有连接。
func (h *Hub) Online(code string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.byCode[code]) > 0
}

// Deliver 把消息投递给某码的全部连接；返回投递成功的连接数（0 表示不在线）。
func (h *Hub) Deliver(code string, v any) int {
	h.mu.RLock()
	targets := make([]Conn, 0, len(h.byCode[code]))
	for c := range h.byCode[code] {
		targets = append(targets, c)
	}
	h.mu.RUnlock()

	n := 0
	for _, c := range targets {
		if err := c.Send(v); err == nil {
			n++
		}
	}
	return n
}

// Subscribe 更新某连接的订阅集合，返回当前快照（按订阅顺序无关）。
func (h *Hub) Subscribe(c Conn, codes []string) map[string]bool {
	h.mu.Lock()
	set := h.subs[c]
	if set == nil {
		set = map[string]struct{}{}
		h.subs[c] = set
	}
	snapshot := make(map[string]bool, len(codes))
	for _, code := range codes {
		if len(code) != 4 {
			continue
		}
		set[code] = struct{}{}
		snapshot[code] = len(h.byCode[code]) > 0
	}
	h.mu.Unlock()
	return snapshot
}

// Presence 返回某码是否在线（供订阅回执用）。
func (h *Hub) Presence(code string) bool { return h.Online(code) }

// notifyPresence 向订阅了该码的连接推送 PRESENCE_CHANGED。
func (h *Hub) notifyPresence(code string, online bool) {
	h.mu.RLock()
	targets := make([]Conn, 0, 8)
	for c, set := range h.subs {
		if _, ok := set[code]; ok {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()

	msg := map[string]any{"type": "PRESENCE_CHANGED", "payload": map[string]any{"code": code, "online": online}}
	for _, c := range targets {
		_ = c.Send(msg)
	}
}
