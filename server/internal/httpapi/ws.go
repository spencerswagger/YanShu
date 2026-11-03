package httpapi

// /v1/ws：直传信令（API.md §9）。只做转发与在线状态，不解析 SDP/候选。
//
// 设计取舍：
//   - 一个码允许**多条**连接（多端/多标签页）；发给该码的帧投递到它的全部连接。
//   - HELLO 必须在 10 秒内到达并验签通过，否则按契约关闭：超时 4408、验签失败 4401。
//   - 帧大小上限 64 KiB（§9.4），超限回 ERROR{SIGNAL_TOO_LARGE} 并关闭。
//   - 每连接令牌桶限速（40 帧/秒，突发 80），超限 ERROR{RATE_LIMITED,fatal:true} 后关闭。
//   - 未认证连接不能发任何帧；收到非 HELLO 即关闭 4401。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/spec"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

const (
	wsCloseAuth         = 4401
	wsCloseHelloTimeout = 4408
	wsMaxFrameBytes     = 64 << 10

	wsFrameRate  = 40.0
	wsFrameBurst = 80.0

	wsHeartbeatMS = 25000
)

// wsFrame 是 §9.2 的信封。
type wsFrame struct {
	Type    string          `json:"type"`
	Seq     int64           `json:"seq,omitempty"`
	TS      string          `json:"ts,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type wsConn struct {
	c    *websocket.Conn
	code string
	seq  atomic.Int64
	mu   sync.Mutex
}

func (w *wsConn) Code() string { return w.code }

// Send 按 §9.2 组装信封（服务端填 seq/ts）后发送。
func (w *wsConn) Send(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var frame map[string]any
	if err := json.Unmarshal(payload, &frame); err != nil {
		return err
	}
	if _, ok := frame["seq"]; !ok {
		frame["seq"] = w.seq.Add(1)
	}
	if _, ok := frame["ts"]; !ok {
		frame["ts"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	}
	out, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return w.c.Write(ctx, websocket.MessageText, out)
}

// handleWS 把 /v1/ws 从 503 占位升级为最小可用信令。
func (a *API) handleWS(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// 鉴权靠 HELLO 签名而不是 Origin：部署常在同源反代之后，Origin 可能被改写。
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		return
	}
	c.SetReadLimit(wsMaxFrameBytes + 1024)
	defer c.CloseNow()

	// ---- 1) HELLO（10 秒内）----
	helloCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	_, data, err := c.Read(helloCtx)
	if err != nil {
		_ = c.Close(wsCloseHelloTimeout, "HELLO timeout")
		return
	}
	var hello wsFrame
	if err := json.Unmarshal(data, &hello); err != nil || hello.Type != "HELLO" {
		_ = c.Close(wsCloseAuth, "HELLO required")
		return
	}
	var hp struct {
		Code        string `json:"code"`
		ChallengeID string `json:"challenge_id"`
		Signature   string `json:"signature"`
	}
	if err := json.Unmarshal(hello.Payload, &hp); err != nil {
		_ = c.Close(wsCloseAuth, "bad HELLO payload")
		return
	}
	code, err := a.verifyWSHello(r.Context(), hp.Code, hp.ChallengeID, hp.Signature)
	if err != nil {
		_ = c.Close(wsCloseAuth, "HELLO rejected")
		return
	}

	conn := &wsConn{c: c, code: code}
	if err := conn.Send(map[string]any{
		"type": "HELLO_OK",
		"payload": map[string]any{
			"code":         code,
			"server_time":  a.now().UTC().Format("2006-01-02T15:04:05Z"),
			"heartbeat_ms": wsHeartbeatMS,
		},
	}); err != nil {
		return
	}

	a.hub.Add(conn, code)
	defer a.hub.Remove(conn)

	// ---- 2) 主循环 ----
	tokens := wsFrameBurst
	last := time.Now()
	for {
		_, data, err := c.Read(context.Background())
		if err != nil {
			return
		}

		// 令牌桶：每帧 1 个令牌，按时间补充。
		now := time.Now()
		tokens += now.Sub(last).Seconds() * wsFrameRate
		if tokens > wsFrameBurst {
			tokens = wsFrameBurst
		}
		last = now
		if tokens < 1 {
			_ = conn.Send(map[string]any{"type": "ERROR", "payload": map[string]any{
				"code": string(spec.ErrRateLimited), "message": "too many signaling frames", "fatal": true,
			}})
			_ = c.Close(wsCloseAuth, "rate limited")
			return
		}
		tokens--

		if len(data) > wsMaxFrameBytes {
			_ = conn.Send(map[string]any{"type": "ERROR", "payload": map[string]any{
				"code": string(spec.ErrSignalTooLarge), "message": "signaling frame exceeds 64 KiB", "fatal": true,
			}})
			_ = c.Close(wsCloseAuth, "signal too large")
			return
		}

		var f wsFrame
		if err := json.Unmarshal(data, &f); err != nil {
			continue // 未知/坏帧：忽略，不断连（§9.2 扩展兼容）
		}
		if !a.handleWSFrame(r.Context(), conn, f) {
			return
		}
	}
}

// verifyWSHello 校验 WS_HELLO 签名，返回归一化后的码。
func (a *API) verifyWSHello(ctx context.Context, code, challengeID, sigB64 string) (string, error) {
	norm, err := gm.NormalizeCode(code)
	if err != nil || len(norm) != 4 {
		return "", errors.New("bad code")
	}
	if challengeID == "" || sigB64 == "" {
		return "", errors.New("missing challenge/signature")
	}
	// ConsumeChallenge 成功后返回的 Used 已置 true，不能再拿它做"是否被用过"的判断。
	ch, err := a.store.ConsumeChallenge(ctx, challengeID, a.now())
	if err != nil {
		return "", errors.New("challenge consumed or expired")
	}
	if ch.Purpose != spec.PurposeWSHello {
		return "", errors.New("wrong challenge purpose")
	}
	rec, err := a.store.GetCode(ctx, norm)
	if err != nil {
		return "", err
	}
	fields, err := auth.WSHelloFields(norm)
	if err != nil {
		return "", err
	}
	input := auth.BuildSignInput(spec.PurposeCodeWSHello, ch.Nonce, fields)
	sig, err := auth.B64.DecodeString(sigB64)
	if err != nil {
		return "", err
	}
	if err := a.verifier.Verify(rec.PublicKey, input, sig); err != nil {
		return "", err
	}
	return norm, nil
}

// handleWSFrame 处理一帧；返回 false 表示应关闭连接。
func (a *API) handleWSFrame(ctx context.Context, conn *wsConn, f wsFrame) bool {
	switch f.Type {
	case "PING":
		_ = conn.Send(map[string]any{"type": "PONG", "payload": map[string]any{}})
		return true

	case "PRESENCE_SUBSCRIBE":
		var p struct {
			Codes []string `json:"codes"`
		}
		_ = json.Unmarshal(f.Payload, &p)
		if len(p.Codes) > 32 {
			p.Codes = p.Codes[:32]
		}
		snapshot := a.hub.Subscribe(conn, p.Codes)
		entries := make([]map[string]any, 0, len(snapshot))
		for c, online := range snapshot {
			entries = append(entries, map[string]any{"code": c, "online": online})
		}
		_ = conn.Send(map[string]any{"type": "PRESENCE_SNAPSHOT", "payload": map[string]any{"entries": entries}})
		return true

	case "RTC_OFFER", "RTC_ANSWER", "RTC_ICE", "RTC_BYE":
		return a.forwardSignal(ctx, conn, f)

	default:
		// 未知 type：按 §9.2 忽略，不断连。
		return true
	}
}

// forwardSignal 做归属校验后原样转发（不解析 SDP/候选内容）。
func (a *API) forwardSignal(ctx context.Context, conn *wsConn, f wsFrame) bool {
	var p struct {
		TransferID string          `json:"transfer_id"`
		ToCode     string          `json:"to_code"`
		SDP        string          `json:"sdp,omitempty"`
		Candidate  json.RawMessage `json:"candidate,omitempty"`
		Reason     string          `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(f.Payload, &p); err != nil {
		return true
	}
	t, err := a.store.GetTransfer(ctx, p.TransferID)
	if err != nil {
		a.wsError(conn, spec.ErrSignalPeerMismatch, "unknown transfer")
		return true
	}
	to, err := gm.NormalizeCode(p.ToCode)
	if err != nil || len(to) != 4 {
		a.wsError(conn, spec.ErrSignalPeerMismatch, "bad to_code")
		return true
	}
	// 当事人校验：发送者必须是该传输的 sender 或 recipient，且收件人是对端。
	switch conn.code {
	case t.SenderCode:
		if to != t.RecipientCode {
			a.wsError(conn, spec.ErrSignalPeerMismatch, "to_code is not the recipient")
			return true
		}
	case t.RecipientCode:
		if to != t.SenderCode {
			a.wsError(conn, spec.ErrSignalPeerMismatch, "to_code is not the sender")
			return true
		}
	default:
		a.wsError(conn, spec.ErrSignalPeerMismatch, "not a party of this transfer")
		return true
	}

	out := map[string]any{"type": f.Type, "payload": map[string]any{
		"transfer_id": p.TransferID,
		"from_code":   conn.code,
	}}
	switch f.Type {
	case "RTC_OFFER", "RTC_ANSWER":
		out["payload"].(map[string]any)["sdp"] = p.SDP
	case "RTC_ICE":
		out["payload"].(map[string]any)["candidate"] = json.RawMessage(p.Candidate)
	case "RTC_BYE":
		out["payload"].(map[string]any)["reason"] = p.Reason
	}

	if a.hub.Deliver(to, out) == 0 {
		_ = conn.Send(map[string]any{"type": "PEER_UNREACHABLE", "payload": map[string]any{
			"transfer_id": p.TransferID, "code": to,
		}})
	}
	return true
}

func (a *API) wsError(conn *wsConn, code spec.ErrorCode, message string) {
	_ = conn.Send(map[string]any{"type": "ERROR", "payload": map[string]any{
		"code": string(code), "message": message, "fatal": false,
	}})
}

// unused guard: keep strings imported when trimming.
var _ = strings.TrimSpace
var _ = store.Transfer{}
