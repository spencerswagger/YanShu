package httpapi

// /v1/ws 直传信令的集成测试（API.md §9）：认证、转发、当事人校验、离线与限速。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

type wsClient struct {
	t    *testing.T
	c    *websocket.Conn
	code string
}

func dialWS(t *testing.T, baseURL, code, challengeID, sig string) *wsClient {
	t.Helper()
	url := "ws" + strings.TrimPrefix(baseURL, "http") + spec.PathWS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	t.Cleanup(func() { c.CloseNow() })

	hello := map[string]any{
		"type": "HELLO",
		"payload": map[string]any{
			"code": code, "challenge_id": challengeID, "signature": sig,
			"client": map[string]string{"platform": "test", "version": "0"},
		},
	}
	writeWS(t, c, hello)
	return &wsClient{t: t, c: c, code: code}
}

func writeWS(t *testing.T, c *websocket.Conn, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatalf("ws write: %v", err)
	}
}

func readWS(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("ws frame: %v", err)
	}
	return m
}

// 两端连接 → 交换 OFFER/ICE → 帧被转发且 from_code 正确；非当事人被拒。
func TestWSSignalForwardingAndPartyCheck(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	outsider, _ := e.register("outsider")

	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	a := dialWS(t, e.srv.URL, sender, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	if got := readWS(t, a.c); got["type"] != "HELLO_OK" {
		t.Fatalf("A hello: %v", got)
	}
	b := dialWS(t, e.srv.URL, recipient, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	if got := readWS(t, b.c); got["type"] != "HELLO_OK" {
		t.Fatalf("B hello: %v", got)
	}

	// A → B 的 OFFER 被转发。
	writeWS(t, a.c, map[string]any{"type": "RTC_OFFER", "payload": map[string]any{
		"transfer_id": tr.TransferID, "to_code": recipient, "sdp": "v=0...offer",
	}})
	got := readWS(t, b.c)
	if got["type"] != "RTC_OFFER" {
		t.Fatalf("B should receive RTC_OFFER, got %v", got)
	}
	payload := got["payload"].(map[string]any)
	if payload["from_code"] != sender || payload["sdp"] != "v=0...offer" {
		t.Fatalf("forwarded payload wrong: %v", payload)
	}
	if _, ok := got["seq"].(float64); !ok {
		t.Fatalf("server frame must carry seq: %v", got)
	}

	// B → A 的 ICE 被转发。
	writeWS(t, b.c, map[string]any{"type": "RTC_ICE", "payload": map[string]any{
		"transfer_id": tr.TransferID, "to_code": sender,
		"candidate": map[string]any{"candidate": "candidate:1 1 UDP 1 192.0.2.1 5000 typ host"},
	}})
	got = readWS(t, a.c)
	if got["type"] != "RTC_ICE" {
		t.Fatalf("A should receive RTC_ICE, got %v", got)
	}

	// 非当事人 → SIGNAL_PEER_MISMATCH。
	o := dialWS(t, e.srv.URL, outsider, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, o.c) // HELLO_OK
	writeWS(t, o.c, map[string]any{"type": "RTC_OFFER", "payload": map[string]any{
		"transfer_id": tr.TransferID, "to_code": recipient, "sdp": "x",
	}})
	errFrame := readWS(t, o.c)
	if errFrame["type"] != "ERROR" {
		t.Fatalf("outsider should get ERROR, got %v", errFrame)
	}
	if code := errFrame["payload"].(map[string]any)["code"]; code != string(spec.ErrSignalPeerMismatch) {
		t.Fatalf("want SIGNAL_PEER_MISMATCH, got %v", code)
	}
}

// 对端不在线 → PEER_UNREACHABLE（客户端据此静默走中转）。
func TestWSSignalPeerUnreachable(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	a := dialWS(t, e.srv.URL, sender, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, a.c) // HELLO_OK

	writeWS(t, a.c, map[string]any{"type": "RTC_OFFER", "payload": map[string]any{
		"transfer_id": tr.TransferID, "to_code": recipient, "sdp": "x",
	}})
	got := readWS(t, a.c)
	if got["type"] != "PEER_UNREACHABLE" {
		t.Fatalf("want PEER_UNREACHABLE, got %v", got)
	}
}

// 未认证先发帧 → 关闭 4401。
func TestWSRequiresHelloFirst(t *testing.T) {
	e := newEnv(t, "")
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + spec.PathWS
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.CloseNow()
	writeWS(t, c, map[string]any{"type": "PING", "payload": map[string]any{}})

	readCtx, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if _, _, err := c.Read(readCtx); err == nil {
		t.Fatal("expected close, got a frame")
	} else if websocket.CloseStatus(err) != wsCloseAuth {
		t.Fatalf("want close 4401, got %v (status %v)", err, websocket.CloseStatus(err))
	}
}

// PING/PONG 与 PRESENCE 快照。
func TestWSPingAndPresence(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")

	a := dialWS(t, e.srv.URL, sender, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, a.c)
	b := dialWS(t, e.srv.URL, recipient, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, b.c) // 等 B 完成 HELLO_OK，确保在线表已登记

	writeWS(t, a.c, map[string]any{"type": "PING", "payload": map[string]any{}})
	if got := readWS(t, a.c); got["type"] != "PONG" {
		t.Fatalf("want PONG, got %v", got)
	}

	writeWS(t, a.c, map[string]any{"type": "PRESENCE_SUBSCRIBE", "payload": map[string]any{
		"codes": []string{recipient},
	}})
	got := readWS(t, a.c)
	if got["type"] != "PRESENCE_SNAPSHOT" {
		t.Fatalf("want PRESENCE_SNAPSHOT, got %v", got)
	}
	entries := got["payload"].(map[string]any)["entries"].([]any)
	if len(entries) != 1 || entries[0].(map[string]any)["online"] != true {
		t.Fatalf("presence entry wrong: %v", entries)
	}
}

// 断连后在线表摘除：订阅方应收到 PRESENCE_CHANGED{online:false}，且快照变为离线。
func TestWSDisconnectRemovesPresence(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")

	a := dialWS(t, e.srv.URL, sender, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, a.c)
	b := dialWS(t, e.srv.URL, recipient, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, b.c)

	writeWS(t, a.c, map[string]any{"type": "PRESENCE_SUBSCRIBE", "payload": map[string]any{
		"codes": []string{recipient},
	}})
	readWS(t, a.c) // SNAPSHOT

	// B 断开 → A 应收到 PRESENCE_CHANGED(online=false)
	_ = b.c.Close(websocket.StatusNormalClosure, "bye")
	got := readWS(t, a.c)
	if got["type"] != "PRESENCE_CHANGED" {
		t.Fatalf("want PRESENCE_CHANGED, got %v", got)
	}
	if p := got["payload"].(map[string]any); p["online"] != false || p["code"] != recipient {
		t.Fatalf("presence payload wrong: %v", p)
	}
}

// 建包时收件人在线 → 收到 TRANSFER_NOTICE。
func TestWSTransferNotice(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")

	b := dialWS(t, e.srv.URL, recipient, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, b.c) // HELLO_OK

	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil)

	got := readWS(t, b.c)
	if got["type"] != "TRANSFER_NOTICE" {
		t.Fatalf("want TRANSFER_NOTICE, got %v", got)
	}
	if p := got["payload"].(map[string]any); p["transfer_id"] != tr.TransferID || p["sender_code"] != sender {
		t.Fatalf("notice payload wrong: %v", p)
	}
}

// 契约 §11.1：按 IP 新建 WS 连接 10 次/分钟，超限 HTTP 429（带 Retry-After）。
func TestWSConnectionRateLimit(t *testing.T) {
	e := newEnv(t, "")
	code, _ := e.register("heavy")

	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + spec.PathWS
	conns := make([]*websocket.Conn, 0, 10)
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, _, err := websocket.Dial(ctx, url, nil)
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
		// 每条连接完成 HELLO，避免占用未认证态
		writeWS(t, c, map[string]any{"type": "HELLO", "payload": map[string]any{
			"code": code, "challenge_id": e.challenge(spec.PurposeWSHello).ChallengeID, "signature": "sig",
		}})
		readWS(t, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.CloseNow()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, resp, err := websocket.Dial(ctx, url, nil); err == nil {
		t.Fatal("11th connection should be limited")
	} else if resp == nil || resp.StatusCode != 429 {
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		t.Fatalf("want 429, got %d", got)
	} else if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

// 订阅收紧：新增订阅 ≤2 码/秒（突发 2），并发上限 8；超限回 RATE_LIMITED 但保连。
func TestWSPresenceSubscriptionRateAndCap(t *testing.T) {
	e := newEnv(t, "")
	me, _ := e.register("me")
	other, _ := e.register("other")

	a := dialWS(t, e.srv.URL, me, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	readWS(t, a.c) // HELLO_OK

	sub := func(codes ...string) map[string]any {
		writeWS(t, a.c, map[string]any{"type": "PRESENCE_SUBSCRIBE", "payload": map[string]any{"codes": codes}})
		return readWS(t, a.c)
	}
	expectRateLimited := func(frame map[string]any, why string) {
		t.Helper()
		if frame["type"] != "ERROR" {
			t.Fatalf("%s: want ERROR, got %v", why, frame)
		}
		p := frame["payload"].(map[string]any)
		if p["code"] != "RATE_LIMITED" || p["fatal"] != false {
			t.Fatalf("%s: want RATE_LIMITED non-fatal, got %v", why, p)
		}
	}

	// ③ 速率：突发 2，连订第 3 个被拒。
	if got := sub("AAAA"); got["type"] != "PRESENCE_SNAPSHOT" {
		t.Fatalf("1st sub: %v", got)
	}
	if got := sub("BBBB"); got["type"] != "PRESENCE_SNAPSHOT" {
		t.Fatalf("2nd sub: %v", got)
	}
	expectRateLimited(sub("CCCC"), "3rd rapid sub")

	// ④ 被拒后连接保持：PING/PONG 仍可用。
	writeWS(t, a.c, map[string]any{"type": "PING", "payload": map[string]any{}})
	if got := readWS(t, a.c); got["type"] != "PONG" {
		t.Fatalf("connection should stay alive: %v", got)
	}

	// ② 并发上限 8：已订 2 个（AAAA/BBBB），再慢慢订 6 个（含真实码 other），第 9 个被拒。
	time.Sleep(600 * time.Millisecond)
	if got := sub(other); got["type"] != "PRESENCE_SNAPSHOT" {
		t.Fatalf("sub other: %v", got)
	}
	for i := 0; i < 5; i++ {
		time.Sleep(550 * time.Millisecond)
		code := []string{"D001", "D002", "D003", "D004", "D005"}[i]
		if got := sub(code); got["type"] != "PRESENCE_SNAPSHOT" {
			t.Fatalf("sub %s: %v", code, got)
		}
	}
	expectRateLimited(sub("D006"), "9th concurrent sub")

	// ⑤ 拒绝不清空既有订阅、也不中断通知：other 上线 → 仍应收到 PRESENCE_CHANGED。
	_ = dialWS(t, e.srv.URL, other, e.challenge(spec.PurposeWSHello).ChallengeID, "sig")
	got := readWS(t, a.c)
	if got["type"] != "PRESENCE_CHANGED" {
		t.Fatalf("want PRESENCE_CHANGED after cap rejection, got %v", got)
	}
	if p := got["payload"].(map[string]any); p["code"] != other || p["online"] != true {
		t.Fatalf("presence payload wrong: %v", p)
	}
}
