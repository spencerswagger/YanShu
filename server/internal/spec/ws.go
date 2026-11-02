package spec

// 直传信令的 WebSocket 消息类型（骨架）。
//
// 本轮**不实现**真实 WebRTC 逻辑，也不做在线表：`GET /api/v1/ws` 直接回
// 501 not_implemented。这里先把消息类型钉住，避免 Web/Rune 侧各自发明字段。
// 服务端语义只有一句：**只转发候选地址与 SDP，不接触任何密钥材料**。
//
// DRAFT(API.md): 消息类型名、信封结构、是否需要 ack/序号，全部待对齐。

// WebSocket 消息类型常量。
const (
	WSHello           = "hello"            // 客户端上线：{type, code, sessionToken}
	WSHelloAck        = "hello.ack"        // 服务端确认：{type, code, online}
	WSPing            = "ping"             // 心跳
	WSPong            = "pong"             // 心跳应答
	WSSignalOffer     = "signal.offer"     // 发起直传：{type, toCode, sdp}
	WSSignalAnswer    = "signal.answer"    // 应答：{type, toCode, sdp}
	WSSignalCandidate = "signal.candidate" // ICE 候选：{type, toCode, candidate}
	WSSignalBye       = "signal.bye"       // 结束直传
	WSSignalFallback  = "signal.fallback"  // 回落中转提示
	WSError           = "error"            // {type, code, message}
)

// WSFrame 是信令消息的统一信封。
// Payload 一律是**不透明字符串**（SDP/candidate 原文），服务端不解析、不落盘、不记日志。
type WSFrame struct {
	Type    string `json:"type"`
	ToCode  string `json:"toCode,omitempty"`
	Payload string `json:"payload,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
