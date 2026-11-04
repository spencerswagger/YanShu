package signal

import (
	"errors"
	"testing"
)

type fakeConn struct {
	code string
	sent []any
	fail bool
}

func (f *fakeConn) Code() string { return f.code }
func (f *fakeConn) Send(v any) error {
	if f.fail {
		return errors.New("send failed")
	}
	f.sent = append(f.sent, v)
	return nil
}

func TestHubPresenceAndDelivery(t *testing.T) {
	h := New()
	a := &fakeConn{code: "AAAA"}
	b := &fakeConn{code: "AAAA"} // 同一码多端
	c := &fakeConn{code: "BBBB"}

	if h.Online("AAAA") {
		t.Fatal("should start offline")
	}
	h.Add(a, "AAAA")
	h.Add(b, "AAAA")
	if !h.Online("AAAA") {
		t.Fatal("should be online after Add")
	}
	// 发给该码的帧投递到全部连接
	if n := h.Deliver("AAAA", map[string]any{"type": "X"}); n != 2 {
		t.Fatalf("deliver count = %d, want 2", n)
	}
	if len(a.sent) != 1 || len(b.sent) != 1 {
		t.Fatalf("both conns should receive: %d/%d", len(a.sent), len(b.sent))
	}
	// 离线码投递返回 0
	if n := h.Deliver("CCCC", map[string]any{"type": "X"}); n != 0 {
		t.Fatalf("offline deliver = %d, want 0", n)
	}

	// 收到 PRESENCE_CHANGED（订阅 BBBB 在线）
	h.Subscribe(c, []string{"BBBB"})
	h.Add(&fakeConn{code: "BBBB"}, "BBBB")
	if len(c.sent) == 0 {
		t.Fatal("subscriber should get PRESENCE_CHANGED")
	}

	// 摘除：同码还有一条连接时仍在线，全部摘除后离线
	h.Remove(a)
	if !h.Online("AAAA") {
		t.Fatal("still one conn left")
	}
	h.Remove(b)
	if h.Online("AAAA") {
		t.Fatal("should be offline after removing all")
	}
}
