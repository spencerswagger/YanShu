package spec

// 直传信令（WebSocket）的消息类型与关闭码，逐字对齐 docs/API.md §9。
//
// 本轮**不实现**信令与在线表（`/v1/ws` 目前回 503 SERVICE_UNAVAILABLE）；
// 这里先把类型常量钉住，避免 Web/Rune 侧各自发明字段。

// 消息类型（API.md §9.3）。
const (
	WSTypeHello             = "HELLO"
	WSTypeHelloOK           = "HELLO_OK"
	WSTypeError             = "ERROR"
	WSTypePing              = "PING"
	WSTypePong              = "PONG"
	WSTypePresenceSubscribe = "PRESENCE_SUBSCRIBE"
	WSTypePresenceSnapshot  = "PRESENCE_SNAPSHOT"
	WSTypePresenceChanged   = "PRESENCE_CHANGED"
	WSTypeTransferNotice    = "TRANSFER_NOTICE"
	WSTypeTransferState     = "TRANSFER_STATE"
	WSTypeInboxSync         = "INBOX_SYNC"
	WSTypeInboxSnapshot     = "INBOX_SNAPSHOT"
	WSTypeRTCOffer          = "RTC_OFFER"
	WSTypeRTCAnswer         = "RTC_ANSWER"
	WSTypeRTCICE            = "RTC_ICE"
	WSTypeRTCBye            = "RTC_BYE"
	WSTypePeerUnreachable   = "PEER_UNREACHABLE"
)

// 关闭码（API.md §10.4）。
const (
	WSCloseNormal       = 1000
	WSCloseAuthFailed   = 4401
	WSCloseHelloTimeout = 4408
	WSCloseTooManyConns = 4429
	WSCloseOverloaded   = 1013
)

// WSHandshakeTimeout 是首帧 HELLO 的超时（API.md §9.1：10 秒）。
const WSHandshakeTimeout = 10

// WSHeartbeatMs 是心跳间隔（API.md §9.3：25000 ms）。
const WSHeartbeatMs = 25000

// SignalFrameLimit 是信令帧大小上限（API.md §9.4：64 KiB）。
const SignalFrameLimit = 64 << 10

// WSFrame 是信令消息的统一信封（API.md §9.2）。
type WSFrame struct {
	Type    string         `json:"type"`
	Seq     uint64         `json:"seq,omitempty"`
	TS      string         `json:"ts,omitempty"`
	Payload map[string]any `json:"payload,omitempty"`
}
