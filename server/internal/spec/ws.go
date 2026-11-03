package spec

// 直传信令（WebSocket）的消息类型与关闭码，逐字对齐 docs/API.md §9。
//
// 本轮**不实现**信令与在线表：`/v1/ws` 明确返回 **503 SERVICE_UNAVAILABLE**（立即返回，
// 不挂起、不让客户端等待）。契约裁决 D1 规定：客户端收到 503 即视作直传不可用、静默走
// 中转，收件通知改为轮询 `GET /v1/inbox`（间隔 ≥ 30 秒，失败退避至 5 分钟）。
// 服务端侧要保证的就是本条 + inbox 轮询可用（每次轮询仍需一次 INBOX_LIST 挑战签名）。
const (
	// InboxPollMinIntervalSeconds 是客户端轮询 inbox 的最小间隔（契约 D1）。
	InboxPollMinIntervalSeconds = 30
	// InboxPollMaxBackoffSeconds 是轮询失败的最大退避（契约 D1）。
	InboxPollMaxBackoffSeconds = 300
)

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
