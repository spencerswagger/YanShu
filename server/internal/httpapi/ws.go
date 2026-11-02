package httpapi

import (
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// handleWS 是直传信令的**桩**。
//
// 本轮不做真实 WebRTC 逻辑，也不维护在线表；先固定消息类型（见 spec/ws.go），
// 让 Web/Rune 侧不至于各自发明字段。真正实现时这里要做的是：
//  1. 用会话令牌鉴权，绑定 code；
//  2. 维护在线表（code → 连接），只按 toCode 转发候选地址与 SDP；
//  3. **不接触任何密钥材料**，不落盘、不记日志。
func (a *API) handleWS(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, spec.ErrNotImplemented, 0)
}

// handleHealthz 健康检查：DB 通就 ok。
func (a *API) handleHealthz(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if err := a.store.Ping(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, spec.HealthResponse{
		Status:     status,
		APIVersion: spec.APIVersion,
		Contract:   "draft",
	})
}
